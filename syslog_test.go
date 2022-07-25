// Copyright (c) 2022
// Author: Jeff Weisberg <tcp4me.com!jaw>
// Created: 2022-Jul-24 10:41 (EDT)
// Function: test

package syslog

import (
	"fmt"
	"testing"
	"time"
)

func TestSyslog(t *testing.T) {

	l, err := New(
		WithDst("udp", "localhost"),
		WithHostname("localhost.example.com"),
		WithAppName("test"),
		WithProcessId("1234"),
		WithFacilityName("uucp"))

	if err != nil {
		t.Fatalf("error: %v", err)
	}

	m := Message{
		time:    time.Unix(1, 0),
		Message: "foo\nbar",
		SData: []*Structured{
			{
				Name:       "Foo",
				Enterprise: "32473",
				Param: map[string]string{
					"girth": "foo\\bar]s",
				},
			},
		},
	}

	pkt, err := l.marshal(SevInfo, &m)

	if err != nil {
		t.Fatalf("error: %v", err)
	}

	exp := `<70>1 1970-01-01T00:00:01Z localhost.example.com test 1234 - [Foo@32473 girth="foo\\bar\]s"] foo bar`

	if pkt != exp {
		fmt.Printf(">> %s\n!= %s\n", pkt, exp)
		t.Fail()
	}

	err = l.Send(SevInfo, m)

	if err != nil {
		t.Fatalf("error: %v", err)
	}

}
