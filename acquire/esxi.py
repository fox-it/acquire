import logging
import re
import subprocess
from contextlib import contextmanager


@contextmanager
def esxi_memory_context_manager():
    memory = EsxiMemoryManager()

    try:
        memory.setup()
        yield memory
    finally:
        memory.reset()


class EsxiMemoryManager:
    def __init__(self) -> None:
        self.group_id: str = ""
        self.mem_scheme: dict[str, str] = dict()

    def setup(self) -> None:
        """Change the ESXi memory limits of the group to unlimited."""
        self.group_id = self._get_group_id()
        self.mem_scheme = self._get_memory_scheme()
        self._set_memory_limits(max="unlimited", min_limit="unlimited")

    def reset(self) -> None:
        """Put memory limits back to their original values."""
        if self.mem_scheme:
            self._set_memory_limits(max=self.mem_scheme.get("max"), min_limit=self.mem_scheme.get("minLimit"))

    def _execute_vsish_command(self, command: list[str]) -> str:
        """Performs and logs a vsish command."""
        vsish_command = ["vsish", "-e"] + command
        logging.info(f"Executing '{' '.join(vsish_command)}' on ESXi host.")

        output = subprocess.check_output(vsish_command)

        return output.decode("utf-8")

    def _get_group_id(self) -> str:
        """Get the group ID of the current session."""
        group_id = self._execute_vsish_command(
            [
                "set",
                "/sched/groupPathNameToID",
                "host",
                "vim",
                "vimuser",
                "terminal",
                "ssh",
            ]
        )
        group_id = group_id.split(" ")[0]
        if not group_id:
            raise ValueError("Something went wrong, group_id was empty.")

        return group_id

    def _set_memory_limits(self, max: str, min_limit: str) -> None:
        self._execute_vsish_command(
            [
                "set",
                f"/sched/groups/{self.group_id}/memAllocationInMB",
                f"max={max}",
                f"minLimit={min_limit}",
            ]
        )

    def _get_memory_scheme(self) -> dict[str, str]:
        """Retrieve and parse the current memory scheme from an ESXi host."""
        mem_sched_allocation = self._execute_vsish_command(
            [
                "get",
                f"/sched/groups/{self.group_id}/memAllocationInMB",
            ]
        )

        data_pattern = re.compile(r"(\w+):\s*(-?\d+)")
        mem_configuration = data_pattern.findall(mem_sched_allocation)
        mem_shed = dict((x, y) for x, y in mem_configuration)
        return mem_shed
