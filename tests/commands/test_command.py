"""Test f8a_worker.commands.command module."""
import os
import time
import pytest
import subprocess

from f8a_utils.commands import ExternalCommand


def test_success():
    """Test success."""
    assert ExternalCommand(['bash', '-c', 'true']).run() is True


def test_failure():
    """Test failure."""
    assert ExternalCommand(['bash', '-c', 'false']).run() is False


def test_input_validation():
    """Test input validation."""
    with pytest.raises(ValueError):
        ExternalCommand('bash')


def test_failure_raise():
    """Test failure with raise_on_error."""
    with pytest.raises(subprocess.CalledProcessError):
        ExternalCommand(['bash', '-c', 'false']).run(raise_on_error=True)


def test_timeout():
    """Test timeout."""
    assert ExternalCommand(['bash', '-c', 'sleep 10']).run(timeout=1) is False


def test_timeout_raise():
    """Test timeout with raise_on_error."""
    with pytest.raises(subprocess.CalledProcessError):
        ExternalCommand(['bash', '-c', 'sleep 10']).run(timeout=1, raise_on_error=True)


def test_update_env():
    """Test updating environment."""
    cmd = ExternalCommand(['bash', '-c', 'echo -n "You know nothing, ${NAME}..."'])
    assert cmd.run(update_env={'NAME': 'Jon Snow'}) is True
    assert cmd.stdout == 'You know nothing, Jon Snow...'


def test_env():
    """Test replacing environment."""
    cmd = ExternalCommand(['bash', '-c', 'echo -n ${HOME}'])
    assert cmd.run(env={'HOME': '/home/michal'}) is True
    assert cmd.stdout == '/home/michal'


def test_kill_children():
    """Test that child processes are also killed. We don't want any zombies!."""
    cmd = ExternalCommand(['bash', '-c', 'bash -c "sleep 10" & echo -n $!'])
    assert cmd.run(timeout=1) is False
    child_pid = int(cmd.stdout)
    try:
        # All processes in the group should be killed by SIGKILL,
        # but `os.killpg` doesn't wait for them to die...
        time.sleep(3)
        os.kill(child_pid, 0)
    except OSError:
        # there is no process with such pid
        assert True
    else:
        assert False


def test_magic_str():
    """Test str(ExternalCommand)."""
    assert str(ExternalCommand(['java', '-version'])) == 'ExternalCommand: java -version'
