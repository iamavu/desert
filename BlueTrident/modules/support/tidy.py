def tidy_url(target):
    if target.endswith('/'):
        target = target[:-1]
    return target