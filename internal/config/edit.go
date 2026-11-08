package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"slices"

	"gopkg.in/yaml.v3"
)

// AddRecipient adds a named recipient with the given keys (per key type) to
// the config file at path, appending it to each named group (created if
// missing). Comments and the order of existing entries are preserved.
func AddRecipient(path, name string, keys map[string][]string, groups []string) error {
	return editFile(path, func(root *yaml.Node) error {
		recipients := mappingValue(root, "recipients", true)
		if mappingValue(recipients, name, false) != nil {
			return fmt.Errorf("recipient %q already exists", name)
		}
		entry := &yaml.Node{Kind: yaml.MappingNode}
		for _, typ := range KeyTypes {
			vals := keys[typ]
			if len(vals) == 0 {
				continue
			}
			var v *yaml.Node
			if len(vals) == 1 {
				v = scalar(vals[0])
			} else {
				v = &yaml.Node{Kind: yaml.SequenceNode}
				for _, s := range vals {
					v.Content = append(v.Content, scalar(s))
				}
			}
			entry.Content = append(entry.Content, scalar(typ), v)
		}
		if len(entry.Content) == 0 {
			return errors.New("at least one key is required")
		}
		recipients.Content = append(recipients.Content, scalar(name), entry)

		if len(groups) > 0 {
			groupsNode := mappingValue(root, "groups", true)
			for _, g := range groups {
				members := mappingValue(groupsNode, g, false)
				if members == nil {
					members = &yaml.Node{Kind: yaml.SequenceNode, Style: yaml.FlowStyle}
					groupsNode.Content = append(groupsNode.Content, scalar(g), members)
				}
				if members.Kind != yaml.SequenceNode {
					return fmt.Errorf("group %q is not a list", g)
				}
				if !sequenceContains(members, name) {
					members.Content = append(members.Content, scalar(name))
				}
			}
		}
		return nil
	})
}

// RemoveRecipient removes a named recipient from the config file at path,
// along with every reference to it in groups and rules.
func RemoveRecipient(path, name string) error {
	return editFile(path, func(root *yaml.Node) error {
		recipients := mappingValue(root, "recipients", false)
		if recipients == nil || !removeMappingKey(recipients, name) {
			return fmt.Errorf("recipient %q does not exist", name)
		}
		if groups := mappingValue(root, "groups", false); groups != nil {
			for i := 1; i < len(groups.Content); i += 2 {
				removeFromSequence(groups.Content[i], name)
			}
		}
		if rules := mappingValue(root, "rules", false); rules != nil && rules.Kind == yaml.SequenceNode {
			for _, rule := range rules.Content {
				if r := mappingValue(rule, "recipients", false); r != nil {
					removeFromSequence(r, name)
				}
			}
		}
		return nil
	})
}

// editFile applies fn to the document's root mapping, validates the result,
// and writes it back only if it is a valid config.
func editFile(path string, fn func(root *yaml.Node) error) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return err
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return errors.New("config must be a YAML mapping")
	}
	if err := fn(doc.Content[0]); err != nil {
		return err
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	if _, err := Parse(buf.Bytes()); err != nil {
		return fmt.Errorf("resulting config is invalid: %w", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), info.Mode().Perm())
}

func scalar(v string) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v} }

// mappingValue returns the value node for key in mapping m, creating an empty
// mapping under that key when create is set.
func mappingValue(m *yaml.Node, key string, create bool) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			v := m.Content[i+1]
			if create && v.Kind == yaml.ScalarNode && v.Tag == "!!null" {
				*v = yaml.Node{Kind: yaml.MappingNode}
			}
			return v
		}
	}
	if !create {
		return nil
	}
	v := &yaml.Node{Kind: yaml.MappingNode}
	m.Content = append(m.Content, scalar(key), v)
	return v
}

func removeMappingKey(m *yaml.Node, key string) bool {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content = slices.Delete(m.Content, i, i+2)
			return true
		}
	}
	return false
}

func sequenceContains(s *yaml.Node, v string) bool {
	return slices.ContainsFunc(s.Content, func(n *yaml.Node) bool { return n.Value == v })
}

func removeFromSequence(s *yaml.Node, v string) {
	if s.Kind != yaml.SequenceNode {
		return
	}
	s.Content = slices.DeleteFunc(s.Content, func(n *yaml.Node) bool { return n.Value == v })
}
