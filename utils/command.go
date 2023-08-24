package utils

import (
	"context"
	"fmt"
	"os/exec"
	"reflect"
)

type Command struct {
	Name string
}

func (c Command) Unmarshal(val interface{}) *exec.Cmd {
	name, args := c.GetCmdArgs(val)
	return exec.Command(name, args...)
}

func (c Command) UnmarshalWithCtx(ctx context.Context, val interface{}) *exec.Cmd {
	name, args := c.GetCmdArgs(val)
	return exec.CommandContext(ctx, name, args...)
}

func (c Command) GetCmdArgs(val interface{}) (string, []string) {
	v := reflect.ValueOf(val)

	var options []string
	for i := 0; i < v.NumField(); i++ {
		tag := v.Type().Field(i).Tag.Get(c.Name)
		if v.Field(i).String() == "" || tag == "" {
			continue
		}

		if tag == "-" {
			options = append(options, v.Field(i).String())
		} else {
			options = append(options, fmt.Sprintf("%s=%v", tag, v.Field(i).String()))
		}
	}
	return c.Name, options
}
