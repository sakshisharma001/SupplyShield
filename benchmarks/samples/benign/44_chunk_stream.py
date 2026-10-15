"""Chunking iterator for lists."""
def chunk_list(items, chunk_size: int):
    for i in range(0, len(items), chunk_size):
        yield items[i:i + chunk_size]
