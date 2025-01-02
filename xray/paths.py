class PathGenerator:
    def __init__(self, base_path: str):
        self._base_path = base_path

    def csv(self) -> str:
        return f"{self._base_path}.csv"

    def pcap(self) -> str:
        return f"{self._base_path}.pcap"

    def txt(self) -> str:
        return f"{self._base_path}.txt"

    def png(self) -> str:
        return f"{self._base_path}.png"
