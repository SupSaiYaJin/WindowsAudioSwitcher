import hid

print("=== All Sony (0x054C) HID devices ===")
devs = hid.enumerate(0x054C)
if not devs:
    print("none found, listing devices with 'INZONE' or 'Sony' in name:")
    for d in hid.enumerate():
        name = (d['product_string'] or '')
        if 'inzone' in name.lower() or 'sony' in name.lower():
            devs = [x for x in hid.enumerate() if x['vendor_id'] == d['vendor_id']]
            break

for d in devs:
    print(
        f"pid=0x{d['product_id']:04x}",
        f"usage_page=0x{d['usage_page']:04x}",
        f"usage=0x{d['usage']:04x}",
        f"iface={d['interface_number']}",
        repr(d['product_string']),
    )
    print("   path:", d['path'])
