package violationbuf_test

import (
	"fmt"
	"testing"

	"github.com/rancher-sandbox/runtime-enforcer/internal/violationbuf"
	"github.com/stretchr/testify/require"
)

func TestBufferRecordAndDrain(t *testing.T) {
	buf := violationbuf.NewBuffer()

	buf.Record(violationbuf.ViolationInfo{
		PolicyName:    "pol1",
		Namespace:     "ns1",
		PodName:       "pod1",
		ContainerName: "ctr1",
		ExePath:       "/bin/sh",
		NodeName:      "node1",
		Action:        "monitor",
	})

	records := buf.Drain()
	require.Len(t, records, 1)
	require.Equal(t, "pol1", records[0].PolicyName)
	require.Equal(t, "ns1", records[0].Namespace)

	// After drain, buffer should be empty.
	records = buf.Drain()
	require.Empty(t, records)
}

func TestBufferOverwritesOldest(t *testing.T) {
	buf := violationbuf.NewBuffer()

	// Fill the buffer to capacity.
	for i := range violationbuf.MaxBufferEntries {
		buf.Record(violationbuf.ViolationInfo{
			PolicyName:    fmt.Sprintf("pol-%d", i),
			Namespace:     "ns1",
			PodName:       "pod1",
			ContainerName: "ctr1",
			ExePath:       "/bin/sh",
			NodeName:      "node1",
			Action:        "monitor",
		})
	}

	// Add one more — should overwrite the oldest (pol-0).
	buf.Record(violationbuf.ViolationInfo{
		PolicyName:    "pol-overflow",
		Namespace:     "ns1",
		PodName:       "pod1",
		ContainerName: "ctr1",
		ExePath:       "/bin/sh",
		NodeName:      "node1",
		Action:        "monitor",
	})

	records := buf.Drain()
	require.Len(t, records, violationbuf.MaxBufferEntries)

	// Oldest should now be pol-1 (pol-0 was overwritten).
	require.Equal(t, "pol-1", records[0].PolicyName)
	// Newest should be pol-overflow.
	require.Equal(t, "pol-overflow", records[len(records)-1].PolicyName)
}

func TestBufferDifferentKeys(t *testing.T) {
	buf := violationbuf.NewBuffer()

	buf.Record(violationbuf.ViolationInfo{
		PolicyName:    "pol1",
		Namespace:     "ns1",
		PodName:       "pod1",
		ContainerName: "ctr1",
		ExePath:       "/bin/sh",
		NodeName:      "node1",
		Action:        "monitor",
	})

	buf.Record(violationbuf.ViolationInfo{
		PolicyName:    "pol1",
		Namespace:     "ns1",
		PodName:       "pod2",
		ContainerName: "ctr1",
		ExePath:       "/bin/sh",
		NodeName:      "node1",
		Action:        "monitor",
	})

	records := buf.Drain()
	require.Len(t, records, 2)
}

func TestBufferDrainChronologicalOrder(t *testing.T) {
	buf := violationbuf.NewBuffer()

	for i := range 5 {
		buf.Record(violationbuf.ViolationInfo{
			PolicyName:    fmt.Sprintf("pol-%d", i),
			Namespace:     "ns1",
			PodName:       "pod1",
			ContainerName: "ctr1",
			ExePath:       "/bin/sh",
			NodeName:      "node1",
			Action:        "monitor",
		})
	}

	records := buf.Drain()
	require.Len(t, records, 5)
	for i, rec := range records {
		require.Equal(t, fmt.Sprintf("pol-%d", i), rec.PolicyName)
	}
}
