package bpf

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rancher-sandbox/runtime-enforcer/internal/types/policymode"
	"github.com/stretchr/testify/require"
)

// createShebangScript creates a temporary executable script with the
// given shebang line and returns its path.
func createShebangScript(t *testing.T, interpreter string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.sh")
	require.NoError(t, os.WriteFile(path, []byte("#!"+interpreter+"\n"), 0755), "failed to write shebang script")
	return path
}

func TestShebangScriptLearning(t *testing.T) {
	runner, err := newCgroupRunner(t)
	require.NoError(t, err, "Failed to create cgroup runner")
	defer runner.close()

	const interpreter = "/usr/bin/true"
	scriptPath := createShebangScript(t, interpreter)

	// When a shebang script is executed, the LSM hook fires for
	// both the script and the interpreter. Without the fix, only
	// the interpreter would appear on the learning channel.
	require.NoError(t, runner.runAndFindCommand(&runCommandArgs{
		command:         scriptPath,
		channel:         learningChannel,
		shouldFindEvent: true,
	}), "script path must be learned via the LSM hook")

	// The interpreter itself must NOT appear as a learned event;
	// only the script path should be emitted.
	resolvedInterpreter, err := filepath.EvalSymlinks(interpreter)
	require.NoError(t, err, "failed to resolve interpreter path")
	err = runner.manager.findEventInChannel(learningChannel, runner.cgInfo.id, resolvedInterpreter)
	require.Error(t, err, "interpreter must not be learned, only the script path")

	// Once a policy is active, learning events must stop being emitted.
	mockPolicyID := uint64(44)
	err = runner.manager.GetPolicyUpdateBinariesFunc()(
		mockPolicyID,
		[]string{resolvedInterpreter, scriptPath},
		AddValuesToPolicy,
	)
	require.NoError(t, err)

	err = runner.manager.GetPolicyModeUpdateFunc()(mockPolicyID, policymode.Protect, UpdateMode)
	require.NoError(t, err)

	err = runner.manager.GetCgroupPolicyUpdateFunc()(
		mockPolicyID, []uint64{runner.cgInfo.id}, AddPolicyToCgroups,
	)
	require.NoError(t, err)

	require.NoError(t, runner.runAndFindCommand(&runCommandArgs{
		command:         scriptPath,
		channel:         learningChannel,
		shouldFindEvent: false,
	}), "script path must not be learned once a policy is active")
}

func TestShebangScriptEnforcement(t *testing.T) {
	runner, err := newCgroupRunner(t)
	require.NoError(t, err, "Failed to create cgroup runner")
	defer runner.close()

	const interpreter = "/usr/bin/bash"
	resolvedInterpreter, err := filepath.EvalSymlinks(interpreter)
	require.NoError(t, err, "failed to resolve interpreter path")
	scriptPath := createShebangScript(t, interpreter)

	mockPolicyID := uint64(44)

	// A policy that allows only the interpreter but NOT the script.
	// This simulates the bug: learning captured the interpreter but
	// missed the script path.
	t.Log("Setting up policy with interpreter only (missing script)")
	err = runner.manager.GetPolicyUpdateBinariesFunc()(
		mockPolicyID,
		[]string{resolvedInterpreter},
		AddValuesToPolicy,
	)
	require.NoError(t, err)

	err = runner.manager.GetPolicyModeUpdateFunc()(mockPolicyID, policymode.Protect, UpdateMode)
	require.NoError(t, err)

	err = runner.manager.GetCgroupPolicyUpdateFunc()(
		mockPolicyID, []uint64{runner.cgInfo.id}, AddPolicyToCgroups,
	)
	require.NoError(t, err)

	// The script should be blocked because its path is not in the
	// allowed list, even though the interpreter is.
	t.Log("Executing script with incomplete policy (expect EPERM)")
	require.NoError(t, runner.runAndFindCommand(&runCommandArgs{
		command:         scriptPath,
		channel:         monitoringChannel,
		shouldFindEvent: true,
		shouldEPERM:     true,
	}), "script must be blocked when not in the allowed list")

	// Now add the script to the policy (simulating correct learning).
	t.Log("Adding script path to the allowed list")
	err = runner.manager.GetPolicyUpdateBinariesFunc()(
		mockPolicyID,
		[]string{resolvedInterpreter, scriptPath},
		ReplaceValuesInPolicy,
	)
	require.NoError(t, err)

	// The script should now be allowed.
	t.Log("Executing script with complete policy (expect success)")
	require.NoError(t, runner.runAndFindCommand(&runCommandArgs{
		command:         scriptPath,
		channel:         monitoringChannel,
		shouldFindEvent: false,
	}), "script must be allowed when both script and interpreter are in the allowed list")
}
