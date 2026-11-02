# OCI Deployment Runbook (M8)

Artifact: `target/deanos.qcow2` (~832 KB qcow2, 1 GiB virtual). Values below are
exact; any console path is Menu ☰ → ...

## 1. Object Storage upload
- Storage → Buckets → (root compartment) → Create Bucket: name `deanos-images`
  (defaults: Standard tier, no versioning).
- Open bucket → Objects → Upload → select `deanos.qcow2` → Upload.

## 2. Custom image import
- Compute → Custom Images → Import image:
  - Name: `deanos-v0.1`
  - Operating system: **Generic Linux**
  - Import from Object Storage: bucket `deanos-images`, object `deanos.qcow2`
  - Image type: **QCOW2**
  - Launch mode: **Paravirtualized mode**
- Wait for state **Available** (~2–5 min).
- Image page → **Edit image capabilities**… ensure:
  - Shape compatibility: add **VM.Standard.A1.Flex** (1 OCPU min)
  - Firmware: **UEFI_64** must be allowed/selected
  - Launch mode: PARAVIRTUALIZED (virtio)

## 3. Launch instance
- Compute → Instances → Create instance:
  - Name: `deanos`
  - Image: My images → `deanos-v0.1`
  - Shape: Ampere `VM.Standard.A1.Flex`, **1 OCPU / 6 GB** (Always Free)
  - Networking: create new VCN `deanos-vcn` with public subnet (or reuse),
    **Assign a public IPv4 address = yes**
  - SSH keys: "No SSH keys" (the unikernel has no SSH)
- Create. Instance → RUNNING; note the **public IP**.

## 4. Network ingress
- VCN → Security Lists → Default Security List → Add Ingress Rules:
  - Source 0.0.0.0/0, protocol TCP, destination port **80**
  - Source 0.0.0.0/0, protocol **ICMP** (type 8 allowed; default list already
    allows some ICMP types — add echo if missing)

## 5. Verify live
```sh
curl -s http://<PUBLIC_IP>/health        # {"status":"ok","os":"deanOS",...}
ping -c 3 <PUBLIC_IP>
curl -s -X POST -d '{"name":"widget"}' http://<PUBLIC_IP>/api/items
curl -s http://<PUBLIC_IP>/api/items
```
Serial console (boot log): Instance → Console Connection → Launch Cloud Shell
connection — shows the PL011 `M1..M7` gate output.

## Notes
- The unikernel DHCPs automatically on the primary VNIC and clamps MSS to 1460
  (OCI jumbo-frame PMTUD protection, PLAN.md §2.6).
- Image is stateless: reboot = fresh RAM store.
