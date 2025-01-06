class PathGenerator:

    def __init__(self, wg: str, test_type: str, count: int):
        self.wg = wg
        self.test_type = test_type
        self.count = count

    def _base_path(self) -> str:
        return f"results/xray_{self.wg.lower()}_{self.test_type}_{self.count}"

    def csv(self) -> str:
        return f"{self._base_path()}.csv"

    def pcap(self) -> str:
        return f"{self._base_path()}.pcap"

    def txt(self) -> str:
        return f"{self._base_path()}.txt"

    def png(self) -> str:
        return f"{self._base_path()}.png"
