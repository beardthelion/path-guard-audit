import shutil


def restore(archive: str, dest: str) -> None:
    shutil.unpack_archive(archive, dest)
