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

  Logger.log("✓ Inisialisasi Sheet Berhasil dilakukan!");
}