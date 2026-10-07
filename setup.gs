// ============================================================
//  setupSystem — Fungsi Inisialisasi Sheet Otomatis
//  Jalankan fungsi ini dari Editor Apps Script jika sheet baru dibuat.
// ============================================================
function setupSystem() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();

  // 1. Setup Sheet Laporan Kejadian (Sheet1)
  let sheetData = ss.getSheetByName("Sheet1");
  if (!sheetData) {
    sheetData = ss.insertSheet("Sheet1");
  }
  if (sheetData.getLastRow() === 0) {
    sheetData.appendRow([
      "Timestamp", "Tgl Kejadian", "Nama Siswa", "Kelas",
      "Angkatan", "Kategori", "Kasus / Prestasi", "Tindakan", "URL Bukti", "URL Surat Pernyataan"
    ]);
    sheetData.getRange(1, 1, 1, 10)
      .setFontWeight("bold")
      .setBackground("#1e293b")
      .setFontColor("#ffffff");
  }

  // 2. Setup Sheet Data Siswa (DataSiswa)
  let sheetSiswa = ss.getSheetByName("DataSiswa");
  if (!sheetSiswa) {
    sheetSiswa = ss.insertSheet("DataSiswa");
  }
  if (sheetSiswa.getLastRow() === 0) {
    sheetSiswa.appendRow(["Nama", "Kelas", "Angkatan", "Status"]);
    sheetSiswa.getRange(1, 1, 1, 4)
      .setFontWeight("bold")
      .setBackground("#1e293b")
      .setFontColor("#ffffff");

    // Contoh data awal
    sheetSiswa.appendRow(["AMANDA NURY MAULIDA", "7A", "2025/2026", "AKTIF"]);
    sheetSiswa.appendRow(["APRILIA NAYSA ADELIA", "7A", "2025/2026", "AKTIF"]);
    sheetSiswa.appendRow(["MOHAMMAD ALIF", "7A", "2025/2026", "AKTIF"]);
    sheetSiswa.appendRow(["ANDIKA STIYAWAN", "7A", "2025/2026", "AKTIF"]);
    sheetSiswa.appendRow(["DEWI SINTA", "7A", "2024/2025", "AKTIF"]);
  }

  // 2b. Migrasi: tambahkan kolom Status jika sheet DataSiswa sudah ada tapi belum punya kolom ke-4
  if (sheetSiswa.getLastRow() > 0) {
    const headerSiswa = sheetSiswa.getRange(1, 1, 1, Math.max(4, sheetSiswa.getLastColumn())).getValues()[0];
    if (String(headerSiswa[3] || '').trim().toLowerCase() !== 'status') {
      sheetSiswa.getRange(1, 4).setValue('Status')
        .setFontWeight('bold').setBackground('#1e293b').setFontColor('#ffffff');
      const lastRow = sheetSiswa.getLastRow();
      if (lastRow > 1) {
        const statusRange = sheetSiswa.getRange(2, 4, lastRow - 1, 1);
        const currentValues = statusRange.getValues();
        const filledValues = currentValues.map(function(r) {
          return [String(r[0] || '').trim() || 'AKTIF'];
        });
        statusRange.setValues(filledValues);
      }
      Logger.log("✓ Kolom Status ditambahkan & data lama di-set ke AKTIF.");
    }
  }

  // 3. Setup Sheet Daftar Angkatan (DaftarAngkatan)
  let sheetAngkatan = ss.getSheetByName("DaftarAngkatan");
  if (!sheetAngkatan) {
    sheetAngkatan = ss.insertSheet("DaftarAngkatan");
  }
  if (sheetAngkatan.getLastRow() === 0) {
    sheetAngkatan.appendRow(["Angkatan"]);
    sheetAngkatan.getRange(1, 1)
      .setFontWeight("bold")
      .setBackground("#1e293b")
      .setFontColor("#ffffff");

    sheetAngkatan.appendRow(["2024/2025"]);
    sheetAngkatan.appendRow(["2025/2026"]);
    sheetAngkatan.appendRow(["2026/2027"]);
  }

  // 4. Setup Sheet Log Aktivitas (LogAktivitas)
  let sheetLog = ss.getSheetByName("LogAktivitas");
  if (!sheetLog) {
    sheetLog = ss.insertSheet("LogAktivitas");
  }
  if (sheetLog.getLastRow() === 0) {
    sheetLog.appendRow(["Waktu", "Username", "Role", "Aksi", "Detail", "Device/Browser"]);
    sheetLog.getRange(1, 1, 1, 6)
      .setFontWeight("bold")
      .setBackground("#1e293b")
      .setFontColor("#ffffff");
    sheetLog.setColumnWidth(5, 400);
    sheetLog.setColumnWidth(6, 220);
  }

  // 5. Setup Sheet Data Wali Kelas (WaliKelas) — untuk notifikasi WhatsApp
  let sheetWali = ss.getSheetByName("WaliKelas");
  if (!sheetWali) {
    sheetWali = ss.insertSheet("WaliKelas");
  }
  if (sheetWali.getLastRow() === 0) {
    sheetWali.appendRow(["Kelas", "Nama Wali Kelas", "No. WhatsApp"]);
    sheetWali.getRange(1, 1, 1, 3)
      .setFontWeight("bold")
      .setBackground("#1e293b")
      .setFontColor("#ffffff");

    // Contoh data awal — silakan diisi/ubah sesuai data sekolah.
    // Format nomor WA bebas (08xxx atau 62xxx), akan dinormalisasi otomatis oleh sistem.
    sheetWali.appendRow(["7A", "Nama Wali Kelas 7A", "08123456789"]);
    sheetWali.setColumnWidth(2, 200);
    sheetWali.setColumnWidth(3, 160);
    Logger.log("✓ Sheet WaliKelas dibuat. Silakan isi data wali kelas & nomor WA sebenarnya.");
  }

  // 6. Setup Sheet Akun Login (Akun) — menggantikan AUTH_USERS lama.
  //    Superadmin bisa tambah/nonaktifkan akun admin (admin1/admin2/dst)
  //    langsung dari tab "Kelola Akun" di web setelah ini dibuat, tidak
  //    perlu edit sheet ini secara manual.
  let sheetAkun = ss.getSheetByName("Akun");
  if (!sheetAkun) {
    sheetAkun = ss.insertSheet("Akun");
  }
  if (sheetAkun.getLastRow() === 0) {
    sheetAkun.appendRow(["Username", "Password", "Role", "Status"]);
    sheetAkun.getRange(1, 1, 1, 4)
      .setFontWeight("bold")
      .setBackground("#1e293b")
      .setFontColor("#ffffff");

    // Akun default awal — SEGERA ganti password-nya lewat tab "Kelola
    // Akun" (login sebagai superadmin) sebelum sistem dipakai sungguhan.
    DEFAULT_SEED_AKUN.forEach(function(a) {
      sheetAkun.appendRow([a.username, a.password, a.role, "AKTIF"]);
    });
    sheetAkun.setColumnWidth(1, 140);
    sheetAkun.setColumnWidth(2, 140);
    Logger.log("✓ Sheet Akun dibuat dengan akun default. SEGERA ganti password default lewat tab Kelola Akun di web!");
  }

  // 7. Setup Sheet Aturan Sanksi (AturanSanksi) — ambang jumlah pelanggaran
  //    per siswa yang memicu sanksi otomatis. Diisi lewat popup "Atur Sanksi"
  //    di form Input Data (kategori Pelanggaran) atau panel "Aturan & Riwayat
  //    Sanksi" di tab Admin Siswa.
  let sheetAturanSanksi = ss.getSheetByName("AturanSanksi");
  if (!sheetAturanSanksi) {
    sheetAturanSanksi = ss.insertSheet("AturanSanksi");
  }
  if (sheetAturanSanksi.getLastRow() === 0) {
    sheetAturanSanksi.appendRow([
      "Nama Siswa", "Kelas", "Angkatan", "Ambang Pelanggaran", "Jenis Sanksi", "Diatur Oleh", "Tanggal Diatur"
    ]);
    sheetAturanSanksi.getRange(1, 1, 1, 7)
      .setFontWeight("bold")
      .setBackground("#1e293b")
      .setFontColor("#ffffff");
    sheetAturanSanksi.setColumnWidth(5, 260);
    Logger.log("✓ Sheet AturanSanksi dibuat.");
  }

  // 8. Setup Sheet Riwayat Sanksi (RiwayatSanksi) — dicatat OTOMATIS oleh
  //    sistem setiap kali jumlah pelanggaran seorang siswa mencapai kelipatan
  //    ambang di sheet "AturanSanksi". Status default "Belum Selesai", diubah
  //    manual jadi "Selesai" setelah penanganan tuntas.
  let sheetRiwayatSanksi = ss.getSheetByName("RiwayatSanksi");
  if (!sheetRiwayatSanksi) {
    sheetRiwayatSanksi = ss.insertSheet("RiwayatSanksi");
  }
  if (sheetRiwayatSanksi.getLastRow() === 0) {
    sheetRiwayatSanksi.appendRow([
      "Tanggal", "Nama Siswa", "Kelas", "Angkatan", "Jumlah Pelanggaran", "Ambang", "Jenis Sanksi", "Status", "Keterangan"
    ]);
    sheetRiwayatSanksi.getRange(1, 1, 1, 9)
      .setFontWeight("bold")
      .setBackground("#1e293b")
      .setFontColor("#ffffff");
    sheetRiwayatSanksi.setColumnWidth(7, 220);
    sheetRiwayatSanksi.setColumnWidth(9, 220);
    Logger.log("✓ Sheet RiwayatSanksi dibuat.");
  }

  // 9. Setup Sheet Tingkat & Poin (TingkatPoin) — daftar tingkat yang bisa
  //    dipilih pelapor saat kategori laporan "Pelanggaran" atau "Prestasi"
  //    (mis. Ringan/Sedang/Berat), masing-masing dengan nilai poin. Poin ini
  //    otomatis tersimpan ke Sheet1 tiap laporan baru. Diatur lewat panel
  //    "Kelola Tingkat & Poin" di tab Admin Siswa — tidak perlu edit sheet
  //    ini secara manual.
  let sheetTingkatPoin = ss.getSheetByName("TingkatPoin");
  if (!sheetTingkatPoin) {
    sheetTingkatPoin = ss.insertSheet("TingkatPoin");
  }
  if (sheetTingkatPoin.getLastRow() === 0) {
    sheetTingkatPoin.appendRow(["Kategori", "Nama Tingkat", "Poin"]);
    sheetTingkatPoin.getRange(1, 1, 1, 3)
      .setFontWeight("bold")
      .setBackground("#1e293b")
      .setFontColor("#ffffff");

    // Data awal contoh — silakan diubah/ditambah lewat panel "Kelola
    // Tingkat & Poin" di tab Admin Siswa sesuai kebijakan sekolah.
    sheetTingkatPoin.appendRow(["Pelanggaran", "Ringan", 1]);
    sheetTingkatPoin.appendRow(["Pelanggaran", "Sedang", 3]);
    sheetTingkatPoin.appendRow(["Pelanggaran", "Berat", 5]);
    sheetTingkatPoin.appendRow(["Prestasi", "Tingkat Sekolah", 3]);
    sheetTingkatPoin.appendRow(["Prestasi", "Tingkat Kecamatan/Kota", 5]);
    sheetTingkatPoin.appendRow(["Prestasi", "Tingkat Provinsi", 8]);
    sheetTingkatPoin.appendRow(["Prestasi", "Tingkat Nasional", 15]);
    Logger.log("✓ Sheet TingkatPoin dibuat dengan data contoh.");
  }

  Logger.log("✓ Inisialisasi Sheet Berhasil dilakukan!");
}