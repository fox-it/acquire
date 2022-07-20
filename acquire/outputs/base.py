import io


class Output:
    def init(self, target):
        pass

    def write(self, path, fh, size=None, entry=None):
        raise NotImplementedError()

    def write_entry(self, path, entry, size=None):
        with entry.open("rb") as fh:
            self.write(path, fh, size, entry)

    def write_bytes(self, path, data: bytes, size=None):
        stream = io.BytesIO(data)
        self.write(path, stream, size=size)

    def close(self):
        raise NotImplementedError()
