"""A simple-to-use wrapper around subprocess.Popen(), for running external commands."""
import subprocess
import time
import logging
import os
import signal

logger = logging.getLogger(__name__)


class ExternalCommand(object):
    """Wrapper around subprocess.Popen(), for running external commands easily."""

    def __init__(self, cmd):
        """Constructor.

        :param cmd: list, command to be executed
        """
        if not isinstance(cmd, list):
            raise ValueError('cmd must be a list')

        self._cmd = cmd
        self._env = {}

        self.duration = None

        self.stdin = None
        self.stdout = None
        self.stderr = None
        self.rc = None
        self.expired = False

    def run(self, timeout=None, env=None, update_env=None,
            stdin=None, cwd=None, raise_on_error=False):
        """Run the command.

        :param timeout: int, timeout (in seconds), default: no timeout.
        :param env: dict, environment variables for the command.
        :param update_env: dict, additional environment variables for the command.
        :param stdin: str, standard input for the command.
        :param cwd: str, working directory for the command.
        :param raise_on_error: bool, raise subprocess.CalledProcessError() on failure

        :return: True on success, False otherwise. When raise_on_error is True,
                 then an exception is raised on failure.
        """
        return self._exec(
            timeout=timeout,
            env=env,
            update_env=update_env,
            stdin=stdin,
            cwd=cwd,
            raise_on_error=raise_on_error
        )

    def _prep(self):
        """Prepare before running the command."""
        pass

    def _cleanup(self):
        """Cleanup after running the command.

        This method is called always, regardless of success of failure.
        """
        pass

    def _exec(self, timeout=None, env=None, update_env=None,
              stdin=None, cwd=None, raise_on_error=False):

        self._prep()

        if update_env:
            env = env if env is not None else os.environ.copy()
            env.update(self._env)
            env.update(update_env)

        proc = subprocess.Popen(
            self._cmd,
            env=env,
            stdin=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            bufsize=0,
            cwd=cwd,
            preexec_fn=os.setsid
        )

        start_time = time.time()

        logger.debug('Running command "{cmd}"'.format(cmd=''.join(self._cmd)))
        try:
            self.stdout, self.stderr = proc.communicate(timeout=timeout)
            self.rc = proc.returncode

        except subprocess.TimeoutExpired:
            # kill the whole process group - the process and its children
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)

            self.stdout, self.stderr = proc.communicate()
            self.rc = 1
            self.expired = True

            logger.error(
                'Command "{cmd}" timed out after {t} seconds: {stderr}'.format(
                    cmd=' '.join(self._cmd), t=timeout, stderr=self.stderr
                )
            )

        finally:
            self.duration = (time.time() - start_time)
            self._cleanup()

            if not self.rc:
                # success
                logger.debug(
                    'Command {cmd} succeeded in {t} seconds'.format(cmd=self._cmd, t=self.duration)
                )
            else:
                # failure
                # only log non-zero return code error here as timeout errors are logged elsewhere
                if not self.expired:
                    logger.error(
                        'Command "{cmd}" returned {rc}: {stderr}'.format(
                            cmd=' '.join(self._cmd), rc=self.rc, stderr=self.stderr
                        )
                    )

                if raise_on_error:
                    raise subprocess.CalledProcessError(self.rc, self._cmd, self.stderr)
                return False

        return True

    def __str__(self):
        return 'ExternalCommand: ' + ' '.join(self._cmd)
