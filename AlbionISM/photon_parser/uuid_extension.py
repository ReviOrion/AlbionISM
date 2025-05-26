def uuid_stringify(arr, offset=0) -> str | None:
    try:
        return ''.join([[f'{i:02x}' for i in range(256)][arr[offset + i]] + ('-' if i in {3, 5, 7, 9} else '') for i in range(16)]).lower()
    except: return None