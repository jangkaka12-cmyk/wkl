"""Giao diện CryptoShield (Streamlit).

Chạy trong thư mục P256_MLKEM768:   python -m streamlit run Frontend/app.py
Giao diện chỉ gọi lại code của cả nhóm: ThangV2 (trao đổi khóa), Encryp_Package (mã hóa + ký),
Dang_Attack_Lab (tấn công), Benchmark (đo hiệu năng). Alice và Bob chạy trên cùng một máy.
"""

import contextlib
import csv
import io
import sys
import tempfile
import time
import uuid
from pathlib import Path

import streamlit as st

GOC = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GOC))  # để import code của cả nhóm
from ThangV2 import hybrid_kex
from Encryp_Package.package import dec_package
from Encryp_Package.pipeline import open_file, seal_file
from Encryp_Package.signature import gen_ecdsa_key
from Dang_Attack_Lab import attack_lab
from Benchmark import benchmark

st.set_page_config(page_title="CryptoShield", layout="wide")


def hex_ngan(b: bytes, n=24):
    """Hiện n byte đầu dạng hex cho gọn."""
    return b[:n].hex() + ("..." if len(b) > n else "")


# ------------------------------------------------------------------ 1. Tổng quan
def trang_tong_quan():
    st.title("CryptoShield: truyền tệp an toàn ECDH + ML-KEM")
    st.graphviz_chart("""digraph {
        rankdir=LR; node [shape=box, style=rounded, fontsize=20]
        K [label="ECDH +\\nML-KEM-768"]; H [label="HKDF\\n→ khóa phiên"]; E [label="AES-GCM\\n+ chữ ký"]
        B [label="Bob kiểm tra\\nrồi giải mã"]
        K -> H -> E -> B
    }""")

    bang1 = benchmark.OUT / "thi_nghiem_1.csv"
    if bang1.exists():
        dong = {(d["Cài đặt"], d["Lược đồ"]): d for d in csv.DictReader(open(bang1, encoding="utf-8-sig"))}
        ecdh, kem = dong[(benchmark.NHOM, "ECDH P-256")], dong[(benchmark.NHOM, "ML-KEM-768")]
        st.subheader("Một lần thiết lập khóa (số liệu từ Benchmark, code của nhóm)")
        for ten, d in (("ECDH P-256", ecdh), ("ML-KEM-768", kem)):
            c = st.columns(2)
            c[0].metric(f"{ten}: thời gian", f"{float(d['Tổng (ms)']):.1f} ms")
            c[1].metric(f"{ten}: gửi qua mạng", f"{d['Tổng gửi qua mạng (B)']} byte")


# ------------------------------------------------------------------ 2. Gửi / nhận tệp (Alice và Bob cùng máy)
def mo_goi(khoa_bob, khoa_ky_alice, goi_tin, da_nhan):
    """Bob kiểm tra và giải mã một package. Trả về (header, bản rõ); sai ở đâu thì báo lỗi ở đó."""
    # 1. Chống phát lại: mỗi message_id chỉ được nhận một lần
    header = dec_package(goi_tin).header
    if header.message_id in da_nhan:
        raise ValueError(f"message_id {header.message_id} đã nhận rồi -> gói bị phát lại (replay)")

    # 2. Tính lại khóa phiên từ khóa riêng của Bob (kiểm tra luôn transcript hash)
    ecdh, kem = khoa_bob
    phien = hybrid_kex.receiver_establish(ecdh.private_key, kem.private_key, header)

    # 3. Kiểm tra chữ ký, giải mã AES-GCM, kiểm tra kích thước + SHA-256 (code của Tân)
    ban_ro = open_file(goi_tin, phien, khoa_ky_alice)

    da_nhan.add(header.message_id)  # chỉ ghi nhận sau khi package hợp lệ
    return header, ban_ro


def trang_gui_nhan():
    st.title("Gửi / nhận tệp")
    ss = st.session_state  # khóa được tạo lại khi tải lại trang (F5)
    if "khoa_bob" not in ss:
        ss.khoa_bob = hybrid_kex.generate_receiver_keys()  # khóa dài hạn của Bob (ECDH + ML-KEM-768)
        ss.khoa_ky = gen_ecdsa_key()                        # khóa ký ECDSA của Alice
        ss.da_nhan = set()                                  # các message_id Bob đã nhận
        ss.goi_tin, ss.so_lieu = None, None                 # package Alice vừa gửi
    alice, bob = st.columns(2, border=True)

    with alice:
        st.subheader("Alice gửi")
        tep = st.file_uploader("Chọn tệp cần gửi")
        if st.button("Mã hóa, ký và gửi cho Bob", type="primary", disabled=tep is None):
            duong_dan = Path(tempfile.mkdtemp()) / tep.name  # giữ tên tệp gốc để Bob nhận đúng tên
            duong_dan.write_bytes(tep.getvalue())
            ecdh, kem = ss.khoa_bob
            t0 = time.perf_counter()
            phien = hybrid_kex.sender_establish(ecdh.public_key, kem.public_key)
            t1 = time.perf_counter()
            ss.goi_tin = seal_file(str(duong_dan), phien, ss.khoa_ky.pri_key)
            t2 = time.perf_counter()
            ss.so_lieu = (tep.name, (t1 - t0) * 1000, (t2 - t1) * 1000, len(ss.goi_tin))
        if ss.so_lieu:
            ten, kex_ms, ma_hoa_ms, so_byte = ss.so_lieu
            st.success(f"Đã gửi {ten} cho Bob.")
            c = st.columns(3)
            c[0].metric("Thiết lập khóa", f"{kex_ms:.1f} ms")
            c[1].metric("Mã hóa + ký", f"{ma_hoa_ms:.1f} ms")
            c[2].metric("Kích thước package", f"{so_byte} byte")

    with bob:
        st.subheader("Bob nhận")
        if st.button("Nhận và giải mã", type="primary", disabled=ss.goi_tin is None):
            try:
                header, ban_ro = mo_goi(ss.khoa_bob, ss.khoa_ky.pub_key, ss.goi_tin, ss.da_nhan)
            except Exception as e:
                st.error(f"TỪ CHỐI: {type(e).__name__}: {e}")
            else:
                st.success(f"CHẤP NHẬN: đã nhận {header.filename} ({len(ban_ro)} byte)")
                st.download_button(f"Tải về {header.filename}", ban_ro, header.filename, on_click="ignore")
        st.caption("Bấm Nhận lần nữa với cùng package là thử phát lại (replay): Bob sẽ từ chối.")


# ------------------------------------------------------------------ 4. Key Inspector
def trang_key_inspector():
    st.title("Key Inspector: xem một lần trao đổi khóa hybrid")
    if not st.button("Tạo một phiên trao đổi khóa mới", type="primary"):
        return
    bob_ecdh, bob_kem = hybrid_kex.generate_receiver_keys()                        # Bob tạo khóa
    alice = hybrid_kex.sender_establish(bob_ecdh.public_key, bob_kem.public_key)   # Alice: khóa tạm + Encaps
    header = hybrid_kex.make_package_header(alice, group_id="demo", message_id=str(uuid.uuid4()),
                                            filename="demo.txt", plaintext_size=0, plaintext_hash=bytes(32))
    bob = hybrid_kex.receiver_establish(bob_ecdh.private_key, bob_kem.private_key, header)  # Bob: ECDH + Decaps

    cac_khoa = [
        ("Bob → Alice", "Khóa công khai ECDH của Bob", bob_ecdh.public_key),
        ("Bob → Alice", "Khóa công khai ML-KEM-768 của Bob", bob_kem.public_key),
        ("Chỉ Bob giữ", "Khóa riêng ECDH của Bob", bob_ecdh.private_key),
        ("Chỉ Bob giữ", "Khóa riêng ML-KEM-768 của Bob", bob_kem.private_key),
        ("Alice → Bob", "Khóa công khai tạm ECDH của Alice", alice.sender_ecdh_public),
        ("Alice → Bob", "Ciphertext ML-KEM-768", alice.mlkem_ciphertext),
        ("Alice → Bob", "Transcript hash", alice.transcript_hash),
        ("Không gửi", "Khóa phiên Alice tính ra", alice.session_key),
        ("Không gửi", "Khóa phiên Bob tính ra", bob.session_key),
    ]
    st.dataframe([{"Đi đâu": d, "Thành phần": ten, "Kích thước (byte)": len(b), "Giá trị (hex, rút gọn)": hex_ngan(b)}
                  for d, ten, b in cac_khoa], hide_index=True)
    if alice.session_key == bob.session_key:
        st.success("Hai bên tính ra cùng một khóa phiên 32 byte mà khóa này không hề được gửi qua mạng.")


# ------------------------------------------------------------------ 5. Attack Lab
DEMO = {
    "1. Luồng bình thường": attack_lab.normal_flow,
    "2. Sửa ciphertext": attack_lab.demo_tamper_ciphertext,
    "3. Sửa thông tin trao đổi khóa (header)": attack_lab.demo_tamper_header,
    "4. Phát lại gói tin (replay)": attack_lab.demo_replay_attack,
    "5. Thay khóa công khai (MITM)": attack_lab.demo_key_substitution,
}


def trang_attack_lab():
    st.title("Attack Lab")
    st.caption("Chạy các demo trong Dang_Attack_Lab/attack_lab.py của Đăng.")
    for ten, ham in DEMO.items():
        if st.button(ten):
            dau_ra = io.StringIO()
            with contextlib.redirect_stdout(dau_ra):  # bắt chữ demo in ra để hiện lên trang
                ham()
            st.code(dau_ra.getvalue())


# ------------------------------------------------------------------ 6. Benchmark
def trang_benchmark():
    st.title("Benchmark: ECDH và ML-KEM")
    if st.button("Chạy lại benchmark (khoảng 25 giây)"):
        with st.spinner("Đang đo..."):
            benchmark.main()
    if not (benchmark.OUT / "thi_nghiem_1.csv").exists():
        st.warning("Chưa có kết quả, hãy bấm nút chạy benchmark.")
        return
    st.text((benchmark.OUT / "moi_truong.txt").read_text(encoding="utf-8"))
    for ten_csv, anh in [("thi_nghiem_1.csv", ["1_thoi_gian_thiet_lap_khoa.png", "2_kich_thuoc.png"]),
                         ("thi_nghiem_2.csv", ["3_truyen_tep.png"])]:
        st.subheader(ten_csv)
        st.dataframe(list(csv.DictReader(open(benchmark.OUT / ten_csv, encoding="utf-8-sig"))), hide_index=True)
        for a in anh:
            st.image(str(benchmark.OUT / a))


TRANG = {
    "Tổng quan": trang_tong_quan,
    "Gửi / nhận tệp": trang_gui_nhan,
    "Key Inspector": trang_key_inspector,
    "Attack Lab": trang_attack_lab,
    "Benchmark": trang_benchmark,
}
TRANG[st.sidebar.radio("CryptoShield", list(TRANG))]()
