// ============================================================
//  AKUN & PERAN (ROLE)
//  - user (tanpa login/"pengunjung") : HANYA bisa Input Data.
//  - admin      : login, bisa Input Data + Rekap Laporan + Cetak
//                 (Export PDF/Excel) + Grafik Tren. Boleh ada BANYAK akun
//                 admin (admin1, admin2, admin3, dst) — semua punya hak
//                 akses yang sama, tapi identitasnya terpisah supaya bisa
//                 dilacak di Log Aktivitas & dimatikan satu-satu tanpa
//                 mengganggu akun admin lain.
//  - superadmin : login, semua hak admin + akses penuh CRUD (edit/hapus
//                 laporan, kelola data siswa, kelola angkatan) + kontrol
//                 toggle akses edit Admin + KELOLA AKUN (tambah/nonaktifkan/
//                 hapus akun admin & superadmin lain) di bawah ini.
//
//  KELOLA AKUN (khusus Superadmin, lihat tab "Admin Siswa" > "Kelola Akun"):
//  Semua akun login (admin & superadmin) sekarang disimpan di sheet
//  "Akun" — BUKAN lagi hardcode di kode ini — supaya Superadmin bisa
//  menambah akun admin baru (mis. admin1/admin2/admin3, satu per orang)
//  langsung dari tampilan web, dan bisa MENONAKTIFKAN akun tertentu kapan
//  saja (misal kalau dicurigai bocor/disalahgunakan) tanpa perlu mengubah
//  kode. Begitu sebuah akun dinonaktifkan, sesi yang sedang aktif dari
//  akun itu langsung ditolak di server pada aksi berikutnya (lihat
//  _getValidSession), jadi tidak perlu menunggu sesi lamanya kedaluwarsa.
//  Ada juga pengaman bawaan: Superadmin tidak bisa menonaktifkan/menghapus
//  akunnya sendiri yang sedang login, dan tidak bisa menonaktifkan/
//  menghapus superadmin AKTIF terakhir — supaya sistem tidak pernah
//  terkunci total tanpa ada satu pun superadmin yang bisa login.
//
//  TOGGLE AKSES EDIT ADMIN:
//  Secara default Admin hanya bisa MELIHAT (view-only) data Laporan &
//  Data Siswa. Superadmin bisa menyalakan toggle "Akses Edit Admin" (di
//  tab Admin Siswa) supaya Admin langsung bisa edit/hapus/dll — TANPA
//  perlu logout & login ulang pakai akun superadmin. Matikan toggle itu
//  kapan saja untuk mengembalikan Admin ke mode lihat saja.
//
//  DEFAULT_SEED_AKUN dipakai HANYA SEKALI untuk mengisi sheet "Akun" saat
//  sheet itu masih kosong (instalasi baru / migrasi dari versi lama).
//  Setelah itu, tambah/ubah/nonaktifkan akun dilakukan lewat tab
//  "Kelola Akun" di web (oleh Superadmin), BUKAN dengan mengedit array
//  ini. PENTING: tetap disarankan ganti password akun default ini lewat
//  tab Kelola Akun sebelum deploy ke penggunaan nyata!
// ============================================================
const DEFAULT_SEED_AKUN = [
  { username: "admin",      password: "admin1", role: "admin" },
  { username: "superadmin", password: "super1", role: "superadmin" }
];

// Kunci penyimpanan status toggle "Akses Edit Admin" di Script Properties
// (tersimpan di server, berlaku untuk SEMUA sesi/pengguna — bukan cuma
// browser Superadmin yang menyalakannya).
const ADMIN_EDIT_PROPERTY_KEY = 'ADMIN_EDIT_ENABLED';

// ============================================================
//  PIN SUPERADMIN — Lapisan Keamanan Tambahan
//  Selain Username + Password, akun berperan "superadmin" WAJIB
//  memasukkan PIN (6 digit angka) tambahan sebelum berhasil login.
//  PIN ini TIDAK sama dengan password, dan hanya berlaku untuk role
//  superadmin (akun admin biasa tetap cukup Username + Password saja)
//  — tujuannya supaya walaupun username/password superadmin bocor,
//  login tetap ditolak tanpa PIN ini.
//
//  PIN disimpan di Script Properties dalam bentuk HASH (SHA-256 + salt),
//  BUKAN teks polos — jadi walau seseorang bisa melihat isi Script
//  Properties, PIN aslinya tidak langsung terbaca.
//
//  Saat pertama kali sistem ini dipasang, PIN belum diset (supaya
//  Superadmin pertama tetap bisa login). Segera atur PIN lewat tab
//  "Admin Siswa" > "Kelola Akun" > "Atur PIN Superadmin" setelah
//  berhasil login pertama kali. Selama PIN belum diset, login
//  superadmin tetap bisa jalan hanya dengan Username + Password
//  (sama seperti sebelumnya) — begitu PIN diset, PIN WAJIB diisi
//  setiap kali login sebagai superadmin.
// ============================================================
const SUPERADMIN_PIN_PROPERTY_KEY = 'SUPERADMIN_PIN_HASH_V1';
const SUPERADMIN_PIN_SALT = 'bkdigital-smpn2maron-pin-salt-v1';

function _hashPin(pin) {
  const raw = SUPERADMIN_PIN_SALT + '::' + String(pin || '');
  const digestBytes = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, raw, Utilities.Charset.UTF_8);
  return digestBytes.map(function(b) {
    return ('0' + (b & 0xFF).toString(16)).slice(-2);
  }).join('');
}

function _getSuperadminPinHash() {
  return PropertiesService.getScriptProperties().getProperty(SUPERADMIN_PIN_PROPERTY_KEY) || '';
}

function _isSuperadminPinSet() {
  return _getSuperadminPinHash() !== '';
}

function _verifySuperadminPin(pinInput) {
  const hash = _getSuperadminPinHash();
  if (!hash) return false;
  return _hashPin(pinInput) === hash;
}

// Dipanggil dari tab "Kelola Akun" (khusus Superadmin yang SUDAH login)
// untuk mengeset PIN pertama kali atau menggantinya. Kalau PIN sebelumnya
// sudah pernah diset, PIN LAMA wajib benar dulu sebelum bisa diganti —
// supaya kalaupun sesi login seseorang "dibajak" via komputer yang lupa
// logout, PIN tetap tidak bisa diganti sembarangan tanpa tahu PIN lama.
function setSuperadminPin(token, pinLama, pinBaru) {
  try {
    _requireRole(token, ['superadmin']);

    const baru = String(pinBaru || '').trim();
    if (!/^\d{6}$/.test(baru)) {
      return { success: false, message: 'PIN baru harus berupa 6 digit angka.' };
    }

    if (_isSuperadminPinSet()) {
      const lama = String(pinLama || '').trim();
      if (!lama || !_verifySuperadminPin(lama)) {
        _catatLog(token, 'Ubah PIN Superadmin Gagal', 'PIN lama yang dimasukkan salah.');
        return { success: false, message: 'PIN lama yang Anda masukkan salah.' };
      }
    }

    PropertiesService.getScriptProperties().setProperty(SUPERADMIN_PIN_PROPERTY_KEY, _hashPin(baru));
    _catatLog(token, 'Ubah PIN Superadmin', 'PIN Superadmin berhasil ' + (_isSuperadminPinSet() ? 'diubah' : 'diset') + '.');

    return { success: true, message: '✓ PIN Superadmin berhasil disimpan. Mulai sekarang, login sebagai superadmin wajib memasukkan PIN ini.' };
  } catch (e) {
    return { success: false, message: 'Gagal menyimpan PIN: ' + e.toString() };
  }
}

// Dipakai tab "Kelola Akun" untuk menampilkan status (sudah/belum diset)
// tanpa pernah mengirim PIN aslinya ke client.
function getSuperadminPinStatus(token) {
  try {
    _requireRole(token, ['superadmin']);
    return { success: true, isSet: _isSuperadminPinSet() };
  } catch (e) {
    return { success: false, isSet: false };
  }
}

// Kunci penyimpanan toggle AKTIF/NONAKTIF notifikasi WhatsApp per peran
// (user/pengunjung, admin, superadmin) di Script Properties — dikontrol
// khusus oleh Superadmin lewat tab Admin Siswa. Kalau toggle untuk peran
// tertentu dimatikan, laporan yang disimpan oleh peran itu TIDAK akan
// memicu kirim WA ke wali kelas walaupun checkbox "Kirim notifikasi WA?"
// dicentang di form. Default (belum pernah diset) = AKTIF untuk semua peran,
// supaya perilaku sistem tidak berubah sebelum Superadmin mengatur ulang.
const WA_NOTIF_PROPERTY_KEYS = {
  user:       'WA_NOTIF_ENABLED_USER',
  admin:      'WA_NOTIF_ENABLED_ADMIN',
  superadmin: 'WA_NOTIF_ENABLED_SUPERADMIN'
};

// Sesi login disimpan di CacheService (server-side), bukan cuma di
// browser — supaya batasan akses ini benar-benar ditegakkan di server,
// bukan cuma sembunyi-sembunyian tombol di tampilan.
const SESSION_TTL_SECONDS = 6 * 60 * 60; // sesi berlaku 6 jam

// ID Folder Google Drive (Opsional - Jika kosong akan otomatis membuat folder 'Bukti BK Digital')
const FOLDER_ID = '';

const SHEET_DATA     = "Sheet1";
const SHEET_SISWA    = "DataSiswa";
const SHEET_ANGKATAN = "DaftarAngkatan";
const SHEET_LOG       = "LogAktivitas";
const SHEET_WALI      = "WaliKelas";
const SHEET_AKUN      = "Akun";

// Endpoint API Fonnte untuk kirim WhatsApp. Token disimpan di Script
// Properties (bukan di kode), lihat fungsi setFonnteToken().
const FONNTE_SEND_URL = 'https://api.fonnte.com/send';

function doGet() {
  return HtmlService.createTemplateFromFile('index')
    .evaluate()
    .setTitle('Sistem BK Digital — SMPN 2 Maron')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL)
    .addMetaTag('viewport', 'width=device-width, initial-scale=1');
}

// ============================================================
//  API GATEWAY (untuk frontend yang di-hosting TERPISAH, mis. di
//  Cloudflare Pages, dan memanggil Apps Script ini lewat fetch()).
//
//  Frontend mengirim POST dengan Content-Type: text/plain (supaya
//  browser tidak mengirim preflight OPTIONS yang tidak bisa dijawab
//  Apps Script) berisi body JSON: { "fn": "namaFungsi", "args": [...] }.
//
//  HANYA fungsi yang terdaftar di API_WHITELIST di bawah ini yang
//  boleh dipanggil dari luar — supaya fungsi internal (diawali "_")
//  atau fungsi sensitif lain tidak bisa dieksekusi sembarangan dari
//  luar walau nama fungsinya ditebak.
// ============================================================
const API_WHITELIST = {
  checkLogin: checkLogin,
  checkSessionValid: checkSessionValid,
  logoutSesi: logoutSesi,
  getAdminEditStatus: getAdminEditStatus,
  setAdminEditStatus: setAdminEditStatus,
  getWaNotifStatus: getWaNotifStatus,
  setWaNotifStatus: setWaNotifStatus,
  getAuditLog: getAuditLog,
  getDaftarAkun: getDaftarAkun,
  simpanAkun: simpanAkun,
  setStatusAkun: setStatusAkun,
  hapusAkun: hapusAkun,
  getSuperadminPinStatus: getSuperadminPinStatus,
  setSuperadminPin: setSuperadminPin,
  getDaftarSiswa: getDaftarSiswa,
  getDaftarAngkatan: getDaftarAngkatan,
  simpanAngkatan: simpanAngkatan,
  getDataSiswaAdmin: getDataSiswaAdmin,
  simpanDataSiswa: simpanDataSiswa,
  simpanBanyakSiswa: simpanBanyakSiswa,
  hapusDataSiswa: hapusDataSiswa,
  hapusDataSiswaMassal: hapusDataSiswaMassal,
  setAngkatanMassal: setAngkatanMassal,
  setStatusSiswa: setStatusSiswa,
  setStatusMassal: setStatusMassal,
  getDataWaliKelasAdmin: getDataWaliKelasAdmin,
  simpanWaliKelas: simpanWaliKelas,
  hapusWaliKelas: hapusWaliKelas,
  simpanData: simpanData,
  getDashboardStats: getDashboardStats,
  getRekapData: getRekapData,
  editSharedKelompok: editSharedKelompok,
  editData: editData,
  hapusData: hapusData,
  hapusDataMassal: hapusDataMassal,
  editDataMassal: editDataMassal
};

function doPost(e) {
  function respond(payload) {
    // text/plain di sisi CLIENT (request) yang penting untuk hindari
    // preflight; response boleh tetap JSON biasa.
    return ContentService.createTextOutput(JSON.stringify(payload))
      .setMimeType(ContentService.MimeType.JSON);
  }

  try {
    if (!e || !e.postData || !e.postData.contents) {
      return respond({ __error: 'Permintaan kosong atau tidak valid.' });
    }

    const body = JSON.parse(e.postData.contents);
    const fnName = body && body.fn;
    const args = (body && Array.isArray(body.args)) ? body.args : [];

    if (!fnName || !Object.prototype.hasOwnProperty.call(API_WHITELIST, fnName)) {
      return respond({ __error: 'Fungsi "' + fnName + '" tidak dikenal atau tidak diizinkan diakses dari luar.' });
    }

    const result = API_WHITELIST[fnName].apply(null, args);
    return respond(result === undefined ? null : result);
  } catch (err) {
    return respond({ __error: (err && err.message) ? err.message : String(err) });
  }
}

function _getOrCreateTargetFolder() {
  if (typeof FOLDER_ID !== 'undefined' && FOLDER_ID && FOLDER_ID.trim() !== '' && FOLDER_ID !== 'FOLDER_ID_DRIVE_ANDA') {
    try {
      return DriveApp.getFolderById(FOLDER_ID.trim());
    } catch (e) {
      console.warn("Folder ID khusus tidak ditemukan. Beralih ke folder otomatis 'Bukti BK Digital'.", e);
    }
  }
  
  const folderName = "Bukti BK Digital";
  const folders = DriveApp.getFoldersByName(folderName);
  if (folders.hasNext()) {
    return folders.next();
  } else {
    return DriveApp.createFolder(folderName);
  }
}

// Mengambil (atau membuat jika belum ada) subfolder di dalam folder induk target,
// supaya foto bukti kejadian dan foto surat pernyataan tersimpan terpisah rapi:
//   Bukti BK Digital/
//     ├─ Foto Bukti Kejadian/
//     └─ Foto Surat Pernyataan/
function _getOrCreateSubfolder(subfolderName) {
  const parent = _getOrCreateTargetFolder();
  const existing = parent.getFoldersByName(subfolderName);
  if (existing.hasNext()) {
    return existing.next();
  }
  return parent.createFolder(subfolderName);
}

function checkLogin(user, pass, deviceInfo, pin) {
  const u = String(user || '').trim().toLowerCase();
  const p = String(pass || '').trim();
  const device = String(deviceInfo || '').trim().slice(0, 150) || 'Tidak diketahui';
  const akun = _findAkunByUsername(u);

  if (!akun || akun.password !== p) {
    _appendLogRow(u || '-', '-', 'Login Gagal', 'Percobaan login dengan username: "' + (user || '') + '"', device);
    return { success: false, message: "Username atau Password salah!" };
  }

  if (String(akun.status || '').toUpperCase() !== 'AKTIF') {
    _appendLogRow(akun.username, akun.role, 'Login Ditolak (Nonaktif)', 'Percobaan login pakai akun yang sudah dinonaktifkan Superadmin.', device);
    return { success: false, message: "Akun ini telah dinonaktifkan oleh Superadmin. Hubungi Superadmin untuk mengaktifkan kembali." };
  }

  // ==== Lapisan tambahan khusus SUPERADMIN: wajib PIN 6 digit ====
  // Username & password superadmin bisa saja bocor/ditebak, jadi peran
  // superadmin (akses penuh) butuh satu rahasia tambahan yang TIDAK
  // pernah dikirim/disimpan bersama password. Kalau PIN belum pernah
  // diset (instalasi baru), langkah ini dilewati supaya Superadmin
  // pertama tetap bisa masuk untuk mengatur PIN-nya.
  if (akun.role === 'superadmin' && _isSuperadminPinSet()) {
    const pinInput = String(pin || '').trim();
    if (!pinInput) {
      // Username+password sudah benar, tinggal minta PIN-nya di client.
      return { success: false, requirePin: true, message: "Password benar. Masukkan PIN Superadmin untuk melanjutkan." };
    }
    if (!_verifySuperadminPin(pinInput)) {
      _appendLogRow(akun.username, akun.role, 'Login Gagal (PIN Salah)', 'Username & password benar, tapi PIN Superadmin salah.', device);
      return { success: false, requirePin: true, message: "PIN Superadmin salah!" };
    }
  }

  const token = Utilities.getUuid();
  // Simpan role, username & device bersamaan (dipisah "::") supaya audit log
  // tahu SIAPA yang login, rolenya apa, dan pakai device apa — device ini
  // otomatis ikut tercatat di SETIAP aksi sepanjang sesi ini (lihat _catatLog).
  CacheService.getScriptCache().put('sesi_' + token, akun.role + '::' + akun.username + '::' + device, SESSION_TTL_SECONDS);

  const pinBelumDiset = akun.role === 'superadmin' && !_isSuperadminPinSet();
  _appendLogRow(akun.username, akun.role, 'Login', 'Login berhasil.' + (pinBelumDiset ? ' (PIN Superadmin belum diset)' : ''), device);

  return { success: true, message: "Login Berhasil!", role: akun.role, token: token, pinNotSet: pinBelumDiset };
}

function logoutSesi(token) {
  try {
    if (token) {
      const username = _getUsernameFromToken(token);
      const role = _getRoleFromToken(token);
      const device = _getDeviceFromToken(token);
      if (username) _appendLogRow(username, role || '-', 'Logout', 'Logout dari sistem.', device);
      CacheService.getScriptCache().remove('sesi_' + token);
    }
    return { success: true };
  } catch (e) {
    return { success: false };
  }
}

function _getRoleFromToken(token) {
  if (!token) return null;
  const raw = CacheService.getScriptCache().get('sesi_' + token);
  if (!raw) return null;
  return raw.split('::')[0];
}

function _getUsernameFromToken(token) {
  if (!token) return null;
  const raw = CacheService.getScriptCache().get('sesi_' + token);
  if (!raw) return null;
  const parts = raw.split('::');
  return parts[1] || null;
}

// Info device/browser dicatat SEKALI saat login (dikirim dari client, lihat
// getDeviceInfo() di index.html) dan disimpan bareng sesi, supaya SEMUA aksi
// yang dilakukan sepanjang sesi itu (edit/hapus/tambah/dll) otomatis
// tercatat pakai device yang sama di Log Aktivitas — tanpa perlu client
// mengirim ulang info device di setiap aksi.
function _getDeviceFromToken(token) {
  if (!token) return null;
  const raw = CacheService.getScriptCache().get('sesi_' + token);
  if (!raw) return null;
  const parts = raw.split('::');
  return parts[2] || null;
}

// ============================================================
//  KELOLA AKUN — Sheet "Akun" (username, password, role, status)
//  Menggantikan array hardcode AUTH_USERS lama supaya Superadmin bisa
//  menambah akun admin baru (admin1/admin2/admin3/dst) dan menonaktifkan
//  akun tertentu langsung dari web, tanpa perlu ubah kode.
// ============================================================
function _isAkunHeaderRow(row) {
  const nilai = [row[0], row[2]].map(function(v) {
    return String(v || '').trim().toLowerCase();
  });
  return nilai[0] === 'username' && nilai[1] === 'role';
}

// Mengambil sheet "Akun". Kalau sheet belum ada atau masih kosong, buat
// & isi dengan akun default (DEFAULT_SEED_AKUN) supaya sistem tetap bisa
// dipakai login walau setupSystem() belum/lupa dijalankan ulang setelah
// update fitur ini (self-healing migrasi dari versi lama).
function _getAkunSheetAndRows() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  let sheet = ss.getSheetByName(SHEET_AKUN);
  if (!sheet) {
    sheet = ss.insertSheet(SHEET_AKUN);
  }
  if (sheet.getLastRow() === 0) {
    sheet.appendRow(["Username", "Password", "Role", "Status"]);
    sheet.getRange(1, 1, 1, 4).setFontWeight('bold').setBackground('#1e293b').setFontColor('#ffffff');
    DEFAULT_SEED_AKUN.forEach(function(a) {
      sheet.appendRow([a.username, a.password, a.role, "AKTIF"]);
    });
  }

  const values = sheet.getDataRange().getDisplayValues();
  const startRow = (values.length && _isAkunHeaderRow(values[0])) ? 2 : 1;
  const filteredValues = values.slice(startRow - 1);
  return { sheet: sheet, startRow: startRow, values: filteredValues };
}

function _getAllAkunRecords() {
  const data = _getAkunSheetAndRows();
  return data.values
    .map(function(row, index) {
      return {
        rowIndex: data.startRow + index,
        username: String(row[0] || '').trim(),
        password: String(row[1] || ''),
        role: String(row[2] || '').trim().toLowerCase(),
        status: String(row[3] || 'AKTIF').trim().toUpperCase() || 'AKTIF'
      };
    })
    .filter(function(item) {
      return item.username !== '';
    });
}

function _findAkunByUsername(username) {
  const u = String(username || '').trim().toLowerCase();
  if (!u) return null;
  return _getAllAkunRecords().find(function(a) {
    return a.username.toLowerCase() === u;
  }) || null;
}

function _hitungSuperadminAktif(kecualiRowIndex) {
  return _getAllAkunRecords().filter(function(a) {
    return a.role === 'superadmin' && a.status === 'AKTIF' && a.rowIndex !== kecualiRowIndex;
  }).length;
}

// Dipakai di _requireRole/_requireEditAccess: selain mengecek tokennya
// valid, sekarang JUGA mengecek ulang ke sheet "Akun" apakah akun itu
// MASIH AKTIF. Kalau Superadmin baru saja menonaktifkan akun tsb, sesi
// yang sedang berjalan langsung ditolak di percobaan aksi berikutnya
// (tidak perlu menunggu sesi lama itu kedaluwarsa 6 jam) — inilah yang
// membuat toggle nonaktifkan akun benar-benar berfungsi sebagai "kill
// switch" kalau akun dicurigai bocor/disalahgunakan.
function _getValidSession(token) {
  const role = _getRoleFromToken(token);
  const username = _getUsernameFromToken(token);
  if (!role || !username) return null;

  const akun = _findAkunByUsername(username);
  if (!akun || akun.status !== 'AKTIF' || akun.role !== role) {
    // Akun sudah dihapus/dinonaktifkan/rolenya berubah sejak login -> paksa logout sesi ini.
    CacheService.getScriptCache().remove('sesi_' + token);
    return null;
  }
  return { role: role, username: username };
}

// Dipanggil dari client secara berkala (polling) selama sesi admin/superadmin
// aktif, supaya begitu Superadmin menonaktifkan sebuah akun, pengguna akun
// itu langsung "terpental"/logout otomatis di sisi client tanpa perlu
// menunggu aksi berikutnya gagal duluan.
function checkSessionValid(token) {
  try {
    const info = _getValidSession(token);
    if (info) {
      // Sliding session: tiap kali dicek (dipanggil client secara berkala
      // via polling, dan sekali lagi tiap halaman dibuka/refresh lewat
      // pulihkanSesi() di index.html), masa berlaku token di CacheService
      // diperpanjang lagi 6 jam dari SEKARANG. Jadi selama aplikasi masih
      // aktif dipakai, pengguna tidak akan tiba-tiba ke-logout di tengah
      // jalan — sesi baru benar-benar habis kalau memang tidak dibuka sama
      // sekali selama 6 jam berturut-turut.
      const raw = CacheService.getScriptCache().get('sesi_' + token);
      if (raw) CacheService.getScriptCache().put('sesi_' + token, raw, SESSION_TTL_SECONDS);
    }
    return { valid: !!info, role: info ? info.role : null };
  } catch (e) {
    return { valid: false, role: null };
  }
}

// Lempar error kalau token tidak valid/kedaluwarsa atau rolenya tidak
// termasuk yang diizinkan. Dipanggil di baris pertama try{} setiap fungsi
// yang mengubah data (CRUD), supaya tidak bisa dipanggil langsung lewat
// console browser oleh pengguna yang belum login / rolenya tidak cukup.
// ============================================================
//  AUDIT LOG — Mencatat Siapa & Kapan Melakukan Aksi Sensitif
//  Sheet "LogAktivitas" dibuat otomatis saat log pertama ditulis.
//  _appendLogRow: penulisan mentah (dipakai saat token belum/tidak ada,
//  misal percobaan login gagal).
//  _catatLog: wrapper yang otomatis resolve username & role dari token.
// ============================================================
function _appendLogRow(username, role, aksi, detail, device) {
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    let sheet = ss.getSheetByName(SHEET_LOG);
    if (!sheet) {
      sheet = ss.insertSheet(SHEET_LOG);
      sheet.appendRow(["Waktu", "Username", "Role", "Aksi", "Detail", "Device/Browser"]);
      sheet.getRange(1, 1, 1, 6).setFontWeight('bold').setBackground('#1e293b').setFontColor('#ffffff');
      sheet.setColumnWidth(5, 400);
      sheet.setColumnWidth(6, 220);
    }
    // Migrasi: kalau sheet log versi lama cuma punya 5 kolom (belum ada
    // "Device/Browser"), tambahkan kolom ke-6 tanpa mengubah data lama.
    if (sheet.getLastColumn() < 6 || String(sheet.getRange(1, 6).getValue() || '').trim() === '') {
      sheet.getRange(1, 6).setValue('Device/Browser').setFontWeight('bold').setBackground('#1e293b').setFontColor('#ffffff');
      sheet.setColumnWidth(6, 220);
    }
    sheet.appendRow([new Date(), username || '-', role || '-', aksi || '-', detail || '', device || '-']);
  } catch (e) {
    console.warn('Gagal mencatat audit log:', e);
  }
}

function _catatLog(token, aksi, detail) {
  const username = _getUsernameFromToken(token) || '-';
  const role = _getRoleFromToken(token) || '-';
  const device = _getDeviceFromToken(token) || '-';
  _appendLogRow(username, role, aksi, detail, device);
}

// Diambil superadmin di tab "Log Aktivitas". Dikembalikan terbaru dulu,
// dibatasi 500 baris terakhir supaya tetap ringan walau log sudah panjang.
function getAuditLog(token) {
  try {
    _requireRole(token, ['superadmin']);

    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(SHEET_LOG);
    if (!sheet || sheet.getLastRow() < 2) return [];

    const lastRow = sheet.getLastRow();
    const startRow = Math.max(2, lastRow - 499); // maksimal 500 baris terakhir
    const jumlahBaris = lastRow - startRow + 1;
    const jumlahKolom = Math.max(6, sheet.getLastColumn());
    const values = sheet.getRange(startRow, 1, jumlahBaris, jumlahKolom).getDisplayValues();

    return values.reverse(); // terbaru di atas
  } catch (e) {
    console.error('getAuditLog error:', e);
    throw e;
  }
}

function _requireRole(token, allowedRoles) {
  const info = _getValidSession(token);
  if (!info || allowedRoles.indexOf(info.role) === -1) {
    throw new Error('Akses ditolak. Aksi ini butuh login sebagai ' + allowedRoles.join(' atau ') + ', atau sesi Anda sudah tidak berlaku (akun dinonaktifkan/dihapus). Silakan login ulang.');
  }
  return info.role;
}

// ============================================================
//  KELOLA AKUN — CRUD (khusus Superadmin)
//  Ditampilkan di tab "Admin Siswa" > panel "Kelola Akun Admin". Dipakai
//  Superadmin untuk menambah akun admin baru (admin1/admin2/admin3/dst),
//  mengubah password/role, menonaktifkan akun tanpa menghapusnya (kalau
//  dicurigai bocor tapi mau dipakai lagi nanti), atau menghapusnya
//  permanen.
// ============================================================

// Daftar akun ditampilkan TANPA kolom password demi keamanan tampilan —
// password hanya bisa DIUBAH (lewat simpanAkun), bukan dilihat lagi.
function getDaftarAkun(token) {
  try {
    _requireRole(token, ['superadmin']);
    return _getAllAkunRecords().map(function(a) {
      return { rowIndex: a.rowIndex, username: a.username, role: a.role, status: a.status };
    });
  } catch (e) {
    console.error('getDaftarAkun error:', e);
    return [];
  }
}

// Tambah akun baru (rowIndex kosong) atau edit akun yang sudah ada
// (rowIndex diisi). Saat edit, password boleh dikosongkan supaya
// password lama tidak berubah.
function simpanAkun(token, dataAkun) {
  try {
    _requireRole(token, ['superadmin']);

    const username = String((dataAkun && dataAkun.username) || '').trim();
    const password = String((dataAkun && dataAkun.password) || '').trim();
    const role = String((dataAkun && dataAkun.role) || '').trim().toLowerCase();
    const rowIndex = Number(dataAkun && dataAkun.rowIndex);

    if (!username || !/^[A-Za-z0-9_.]{3,50}$/.test(username)) {
      return { success: false, message: 'Username wajib diisi (3-50 karakter, hanya huruf/angka/underscore/titik, tanpa spasi).' };
    }
    if (['admin', 'superadmin'].indexOf(role) === -1) {
      return { success: false, message: 'Role tidak valid. Pilih Admin atau Superadmin.' };
    }

    const existing = _getAllAkunRecords();
    const duplikat = existing.find(function(a) {
      return a.username.toLowerCase() === username.toLowerCase() && a.rowIndex !== rowIndex;
    });
    if (duplikat) {
      return { success: false, message: 'Username "' + username + '" sudah dipakai akun lain. Pilih username lain.' };
    }

    const data = _getAkunSheetAndRows();
    const sheet = data.sheet;

    if (rowIndex && rowIndex > 0) {
      // EDIT akun yang sudah ada.
      const akunLama = existing.find(function(a) { return a.rowIndex === rowIndex; });
      if (!akunLama) {
        return { success: false, message: 'Akun yang ingin diedit tidak ditemukan (mungkin sudah dihapus).' };
      }
      // Cegah menurunkan role superadmin terakhir yang aktif -> supaya
      // sistem tidak pernah kehilangan superadmin sama sekali.
      if (akunLama.role === 'superadmin' && role !== 'superadmin' && akunLama.status === 'AKTIF' && _hitungSuperadminAktif(rowIndex) === 0) {
        return { success: false, message: 'Tidak bisa mengubah role akun ini — ini satu-satunya akun Superadmin yang aktif. Buat/aktifkan superadmin lain dulu sebelum mengubah akun ini.' };
      }
      const passwordBaru = password || akunLama.password;
      if (!password && !akunLama.password) {
        return { success: false, message: 'Password wajib diisi untuk akun ini.' };
      }
      sheet.getRange(rowIndex, 1, 1, 3).setValues([[username, passwordBaru, role]]);
      _catatLog(token, 'Edit Akun', 'Akun "' + username + '" (role: ' + role + ') diperbarui' + (password ? ' — password diganti.' : '.'));
      return { success: true, message: '✓ Akun "' + username + '" berhasil diperbarui.' };
    }

    // TAMBAH akun baru.
    if (!password || password.length < 4) {
      return { success: false, message: 'Password wajib diisi, minimal 4 karakter, untuk akun baru.' };
    }
    if (sheet.getLastRow() === 0) {
      sheet.appendRow(['Username', 'Password', 'Role', 'Status']);
      sheet.getRange(1, 1, 1, 4).setFontWeight('bold').setBackground('#1e293b').setFontColor('#ffffff');
    }
    sheet.appendRow([username, password, role, 'AKTIF']);
    _catatLog(token, 'Tambah Akun', 'Akun baru "' + username + '" (role: ' + role + ') ditambahkan.');
    return { success: true, message: '✓ Akun "' + username + '" berhasil ditambahkan.' };
  } catch (e) {
    return { success: false, message: 'Gagal menyimpan akun: ' + e.toString() };
  }
}

// Aktifkan/nonaktifkan satu akun. Inilah "kill switch" utama yang diminta:
// Superadmin bisa mematikan akun admin (atau superadmin lain) yang sedang
// dipakai/dicurigai bocor, tanpa perlu menghapus datanya.
function setStatusAkun(token, rowIndex, statusBaru) {
  try {
    _requireRole(token, ['superadmin']);

    const idx = Number(rowIndex);
    const status = String(statusBaru || '').trim().toUpperCase();
    if (status !== 'AKTIF' && status !== 'NONAKTIF') {
      return { success: false, message: 'Status tidak valid.' };
    }

    const existing = _getAllAkunRecords();
    const target = existing.find(function(a) { return a.rowIndex === idx; });
    if (!target) {
      return { success: false, message: 'Akun tidak ditemukan.' };
    }

    const usernamePelaku = _getUsernameFromToken(token);
    if (status === 'NONAKTIF' && usernamePelaku && target.username.toLowerCase() === String(usernamePelaku).toLowerCase()) {
      return { success: false, message: 'Anda tidak bisa menonaktifkan akun Anda sendiri yang sedang login. Minta Superadmin lain untuk menonaktifkan akun ini.' };
    }
    if (status === 'NONAKTIF' && target.role === 'superadmin' && _hitungSuperadminAktif(idx) === 0) {
      return { success: false, message: 'Tidak bisa menonaktifkan akun ini — ini satu-satunya akun Superadmin yang aktif. Buat/aktifkan superadmin lain dulu.' };
    }

    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(SHEET_AKUN) || ss.insertSheet(SHEET_AKUN);
    sheet.getRange(idx, 4).setValue(status);

    _catatLog(token, status === 'AKTIF' ? 'Aktifkan Akun' : 'Nonaktifkan Akun', 'Akun "' + target.username + '" (role: ' + target.role + ') di-set menjadi ' + status + '.');
    return {
      success: true,
      message: status === 'AKTIF'
        ? '✓ Akun "' + target.username + '" diaktifkan kembali.'
        : '✓ Akun "' + target.username + '" dinonaktifkan. Sesi login yang sedang aktif dari akun ini akan langsung ditolak.'
    };
  } catch (e) {
    return { success: false, message: 'Gagal mengubah status akun: ' + e.toString() };
  }
}

function hapusAkun(token, rowIndex) {
  try {
    _requireRole(token, ['superadmin']);

    const idx = Number(rowIndex);
    const existing = _getAllAkunRecords();
    const target = existing.find(function(a) { return a.rowIndex === idx; });
    if (!target) {
      return { success: false, message: 'Akun tidak ditemukan.' };
    }

    const usernamePelaku = _getUsernameFromToken(token);
    if (usernamePelaku && target.username.toLowerCase() === String(usernamePelaku).toLowerCase()) {
      return { success: false, message: 'Anda tidak bisa menghapus akun Anda sendiri yang sedang login.' };
    }
    if (target.role === 'superadmin' && target.status === 'AKTIF' && _hitungSuperadminAktif(idx) === 0) {
      return { success: false, message: 'Tidak bisa menghapus akun ini — ini satu-satunya akun Superadmin yang aktif.' };
    }

    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(SHEET_AKUN) || ss.insertSheet(SHEET_AKUN);
    if (idx < 1 || idx > sheet.getLastRow()) {
      return { success: false, message: 'Baris akun tidak valid.' };
    }
    sheet.deleteRow(idx);

    _catatLog(token, 'Hapus Akun', 'Akun "' + target.username + '" (role: ' + target.role + ') dihapus permanen.');
    return { success: true, message: '✓ Akun "' + target.username + '" berhasil dihapus.' };
  } catch (e) {
    return { success: false, message: 'Gagal menghapus akun: ' + e.toString() };
  }
}

// ============================================================
//  TOGGLE AKSES EDIT ADMIN — dikontrol Superadmin
//  Defaultnya Admin cuma bisa lihat (view-only). Superadmin bisa
//  menyalakan togglenya supaya Admin langsung bisa edit/hapus/dll,
//  tanpa Admin perlu logout & login ulang pakai akun superadmin.
//  Statusnya disimpan di Script Properties (server-side) supaya
//  konsisten untuk semua sesi, bukan cuma sesi yang menyalakannya.
// ============================================================
function _isAdminEditEnabled() {
  try {
    return PropertiesService.getScriptProperties().getProperty(ADMIN_EDIT_PROPERTY_KEY) === 'true';
  } catch (e) {
    return false;
  }
}

// Dipanggil dari client (admin maupun superadmin, bahkan berkala/polling)
// untuk tahu status toggle saat ini, supaya UI Admin otomatis berubah dari
// "Lihat saja" ke "Bisa Edit" begitu Superadmin mengaktifkannya — tanpa
// perlu refresh halaman atau login ulang.
function getAdminEditStatus() {
  try {
    return { success: true, enabled: _isAdminEditEnabled() };
  } catch (e) {
    return { success: false, enabled: false };
  }
}

// Hanya Superadmin yang boleh mengubah toggle ini.
function setAdminEditStatus(token, aktif) {
  try {
    _requireRole(token, ['superadmin']);
    const enabled = !!aktif;
    PropertiesService.getScriptProperties().setProperty(ADMIN_EDIT_PROPERTY_KEY, enabled ? 'true' : 'false');
    _catatLog(token, 'Ubah Akses Edit Admin', enabled
      ? 'Akses edit/hapus untuk Admin DIAKTIFKAN.'
      : 'Akses edit/hapus untuk Admin DINONAKTIFKAN (Admin kembali ke mode lihat saja).');
    return {
      success: true,
      enabled: enabled,
      message: enabled
        ? '✓ Akses edit/hapus untuk Admin diaktifkan. Admin tidak perlu login ulang.'
        : '✓ Akses edit/hapus untuk Admin dinonaktifkan. Admin sekarang hanya bisa melihat data.'
    };
  } catch (e) {
    return { success: false, message: 'Gagal mengubah status akses admin: ' + e.toString() };
  }
}

// Dipakai di semua fungsi CRUD (edit/hapus/tambah/dll) yang sekarang boleh
// diakses Admin JIKA togglenya aktif; Superadmin selalu boleh kapan pun
// terlepas dari status toggle.
function _requireEditAccess(token) {
  const info = _getValidSession(token);
  const role = info ? info.role : null;
  if (role === 'superadmin') return role;
  if (role === 'admin') {
    if (_isAdminEditEnabled()) return role;
    throw new Error('Akses ditolak. Fitur edit/hapus untuk Admin belum diaktifkan oleh Superadmin. Saat ini Admin hanya bisa melihat data.');
  }
  throw new Error('Akses ditolak. Aksi ini butuh login sebagai admin atau superadmin, atau sesi Anda sudah tidak berlaku (akun dinonaktifkan/dihapus). Silakan login ulang.');
}

// ============================================================
//  TOGGLE AKTIF/NONAKTIF NOTIFIKASI WA PER PERAN — dikontrol Superadmin
//  Peran yang diatur: user (pengunjung/tanpa login), admin, superadmin.
//  Dipakai untuk menentukan apakah laporan yang disimpan oleh peran
//  tertentu boleh memicu kirim WA otomatis ke wali kelas atau tidak,
//  terlepas dari checkbox "Kirim notifikasi WA?" di form sudah dicentang.
//  Statusnya disimpan di Script Properties (server-side) supaya berlaku
//  konsisten untuk semua sesi/browser.
// ============================================================

// Peran belum pernah diset -> dianggap AKTIF (default), supaya sistem
// tetap berjalan seperti semula sebelum Superadmin mengatur ulang toggle.
function _isWaNotifEnabledForRole(role) {
  try {
    const key = WA_NOTIF_PROPERTY_KEYS[role];
    if (!key) return true;
    const val = PropertiesService.getScriptProperties().getProperty(key);
    return val === null ? true : val === 'true';
  } catch (e) {
    return true;
  }
}

// Dipanggil dari client (siapa pun, termasuk pengunjung belum login) untuk
// tahu status ketiga toggle saat ini, supaya UI (checkbox WA di form, panel
// kontrol di tab Admin) selalu mencerminkan status server terbaru.
function getWaNotifStatus() {
  try {
    return {
      success: true,
      status: {
        user: _isWaNotifEnabledForRole('user'),
        admin: _isWaNotifEnabledForRole('admin'),
        superadmin: _isWaNotifEnabledForRole('superadmin')
      }
    };
  } catch (e) {
    return { success: false, status: { user: true, admin: true, superadmin: true } };
  }
}

// Hanya Superadmin yang boleh mengubah toggle ini. `role` harus salah satu
// dari 'user', 'admin', 'superadmin'.
function setWaNotifStatus(token, role, aktif) {
  try {
    _requireRole(token, ['superadmin']);
    const key = WA_NOTIF_PROPERTY_KEYS[role];
    if (!key) {
      return { success: false, message: 'Peran tidak dikenali: ' + role };
    }
    const enabled = !!aktif;
    PropertiesService.getScriptProperties().setProperty(key, enabled ? 'true' : 'false');

    const labelPeran = { user: 'User/Pengunjung', admin: 'Admin', superadmin: 'Superadmin' }[role] || role;
    _catatLog(token, 'Ubah Toggle Notifikasi WA', 'Notifikasi WA untuk peran ' + labelPeran + ' di' +
      (enabled ? 'AKTIFKAN' : 'NONAKTIFKAN') + '.');

    return {
      success: true,
      role: role,
      enabled: enabled,
      message: '✓ Notifikasi WA untuk peran ' + labelPeran + ' ' + (enabled ? 'diaktifkan' : 'dinonaktifkan') + '.'
    };
  } catch (e) {
    return { success: false, message: 'Gagal mengubah status notifikasi WA: ' + e.toString() };
  }
}

function _isSiswaHeaderRow(row) {
  const nilai = [row[0], row[1], row[2]].map(function(v) {
    return String(v || '').trim().toLowerCase();
  });
  return nilai[0] === 'nama' && nilai[1] === 'kelas';
}

function _getSiswaSheetAndRows() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_SISWA) || ss.insertSheet(SHEET_SISWA);
  const range = sheet.getDataRange();
  const values = range.getDisplayValues();
  
  if (!values || values.length === 0) {
    return { sheet: sheet, startRow: 1, values: [] };
  }
  
  const startRow = _isSiswaHeaderRow(values[0]) ? 2 : 1;
  const filteredValues = values.slice(startRow - 1);
  return { sheet: sheet, startRow: startRow, values: filteredValues };
}

function _getAngkatanSheetAndRows() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_ANGKATAN) || ss.insertSheet(SHEET_ANGKATAN);
  const range = sheet.getDataRange();
  const values = range.getDisplayValues();
  
  if (!values || values.length === 0) {
    return { sheet: sheet, startRow: 1, values: [] };
  }
  
  const firstCell = String(values[0][0] || '').trim().toLowerCase();
  const startRow = (firstCell === 'angkatan' || firstCell === 'daftar angkatan') ? 2 : 1;
  const filteredValues = values.slice(startRow - 1);
  return { sheet: sheet, startRow: startRow, values: filteredValues };
}

function _getAllSiswaRecords() {
  const data = _getSiswaSheetAndRows();
  return data.values
    .map(function(row, index) {
      return {
        rowIndex: data.startRow + index,
        nama: String(row[0] || '').trim(),
        kelas: String(row[1] || '').trim(),
        angkatan: String(row[2] || '').trim(),
        status: String(row[3] || '').trim() || 'AKTIF'
      };
    })
    .filter(function(item) {
      return item.nama !== '';
    });
}

function getDaftarSiswa() {
  try {
    return _getAllSiswaRecords().map(function(item) {
      return { nama: item.nama, kelas: item.kelas, angkatan: item.angkatan, status: item.status };
    });
  } catch (e) {
    console.error('getDaftarSiswa error:', e);
    return [];
  }
}

function getDaftarAngkatan() {
  try {
    const options = {};
    _getAllSiswaRecords().forEach(function(item) {
      const value = String(item.angkatan || '').trim();
      if (value) options[value] = true;
    });

    const data = _getAngkatanSheetAndRows();
    data.values.forEach(function(row) {
      const value = String(row[0] || '').trim();
      if (value) options[value] = true;
    });

    return Object.keys(options).sort();
  } catch (e) {
    console.error('getDaftarAngkatan error:', e);
    return [];
  }
}

// Logika inti tambah angkatan, TANPA cek token — dipakai secara internal
// oleh fungsi lain (simpanDataSiswa, dst.) yang sudah
// melakukan pengecekan role sendiri di titik masuknya masing-masing.
function _simpanAngkatanInternal(angkatan) {
  const value = String(angkatan || '').trim();
  if (!value) return { success: false, message: 'Angkatan tidak boleh kosong.' };

  const data = _getAngkatanSheetAndRows();
  const sheet = data.sheet;
  const existing = new Set(data.values.map(function(row) {
    return String(row[0] || '').trim();
  }).filter(Boolean));

  if (!existing.has(value)) {
    if (sheet.getLastRow() === 0) {
      sheet.appendRow(['Angkatan']);
    }
    sheet.appendRow([value]);
  }
  return { success: true, message: '✓ Angkatan custom berhasil ditambahkan.' };
}

// Entry point yang dipanggil langsung dari klien (tombol di Admin Siswa) —
// wajib login sebagai superadmin.
function simpanAngkatan(token, angkatan) {
  try {
    _requireEditAccess(token);
    return _simpanAngkatanInternal(angkatan);
  } catch (e) {
    return { success: false, message: 'Gagal menambah angkatan: ' + e.toString() };
  }
}

function editAngkatan(token, dataEdit) {
  try {
    _requireEditAccess(token);

    const oldValue = String((dataEdit && dataEdit.oldValue) || '').trim();
    const newValue = String((dataEdit && dataEdit.newValue) || '').trim();

    if (!oldValue || !newValue) {
      return { success: false, message: 'Angkatan lama dan baru wajib diisi.' };
    }

    const data = _getAngkatanSheetAndRows();
    const sheet = data.sheet;
    const existing = new Set(data.values.map(function(row) {
      return String(row[0] || '').trim();
    }).filter(Boolean));

    if (!existing.has(oldValue)) return { success: false, message: 'Angkatan tidak ditemukan.' };
    if (existing.has(newValue)) return { success: false, message: 'Angkatan baru sudah ada.' };

    const targetRow = data.values.findIndex(function(row) {
      return String(row[0] || '').trim() === oldValue;
    });

    if (targetRow >= 0) {
      sheet.getRange(data.startRow + targetRow, 1).setValue(newValue);
      return { success: true, message: '✓ Angkatan berhasil diperbarui.' };
    }
    return { success: false, message: 'Angkatan tidak ditemukan.' };
  } catch (e) {
    return { success: false, message: 'Gagal mengedit angkatan: ' + e.toString() };
  }
}

function hapusAngkatan(token, angkatan) {
  try {
    _requireEditAccess(token);

    const value = String(angkatan || '').trim();
    if (!value) return { success: false, message: 'Angkatan tidak boleh kosong.' };

    const data = _getAngkatanSheetAndRows();
    const sheet = data.sheet;
    const targetRow = data.values.findIndex(function(row) {
      return String(row[0] || '').trim() === value;
    });

    if (targetRow >= 0) {
      sheet.deleteRow(data.startRow + targetRow);
      return { success: true, message: '✓ Angkatan berhasil dihapus.' };
    }
    return { success: false, message: 'Angkatan tidak ditemukan.' };
  } catch (e) {
    return { success: false, message: 'Gagal menghapus angkatan: ' + e.toString() };
  }
}

function getDataSiswaAdmin(token) {
  try {
    _requireRole(token, ['admin', 'superadmin']);
    return _getAllSiswaRecords();
  } catch (e) {
    console.error('getDataSiswaAdmin error:', e);
    return [];
  }
}

function simpanDataSiswa(token, dataSiswa) {
  try {
    _requireEditAccess(token);

    const data = _getSiswaSheetAndRows();
    const sheet = data.sheet;
    const nama = String((dataSiswa && dataSiswa.nama) || '').trim();
    const kelas = String((dataSiswa && dataSiswa.kelas) || '').trim();
    const angkatan = String((dataSiswa && dataSiswa.angkatan) || '').trim();
    const status = String((dataSiswa && dataSiswa.status) || '').trim() || 'AKTIF';

    if (!nama || !kelas) return { success: false, message: 'Nama dan kelas wajib diisi.' };

    const rowIndex = Number(dataSiswa && dataSiswa.rowIndex);
    if (rowIndex && rowIndex > 0) {
      sheet.getRange(rowIndex, 1, 1, 4).setValues([[nama, kelas, angkatan, status]]);
      _simpanAngkatanInternal(angkatan);
      _catatLog(token, 'Edit Siswa', nama + ' - Kelas ' + kelas + ' - Angkatan ' + angkatan + ' - Status ' + status);
      return { success: true, message: '✓ Data siswa berhasil diperbarui.' };
    }

    sheet.appendRow([nama, kelas, angkatan, status]);
    _simpanAngkatanInternal(angkatan);
    _catatLog(token, 'Tambah Siswa', nama + ' - Kelas ' + kelas + ' - Angkatan ' + angkatan);
    return { success: true, message: '✓ Data siswa berhasil ditambahkan.' };
  } catch (e) {
    return { success: false, message: 'Gagal menyimpan data siswa: ' + e.toString() };
  }
}

function simpanBanyakSiswa(token, daftarArray) {
  try {
    _requireEditAccess(token);

    if (!Array.isArray(daftarArray) || daftarArray.length === 0) {
      return { success: false, message: 'Daftar siswa kosong.' };
    }

    const data = _getSiswaSheetAndRows();
    const sheet = data.sheet;
    const rowsToAdd = [];
    const setAngkatan = new Set();

    daftarArray.forEach(function(item) {
      const nama = String(item.nama || '').trim();
      const kelas = String(item.kelas || '').trim();
      const angkatan = String(item.angkatan || '').trim();
      const status = String(item.status || '').trim() || 'AKTIF';

      if (nama && kelas) {
        rowsToAdd.push([nama, kelas, angkatan, status]);
        if (angkatan) setAngkatan.add(angkatan);
      }
    });

    if (rowsToAdd.length === 0) {
      return { success: false, message: 'Tidak ada data valid untuk ditambahkan.' };
    }

    const startRow = sheet.getLastRow() + 1;
    sheet.getRange(startRow, 1, rowsToAdd.length, 4).setValues(rowsToAdd);

    setAngkatan.forEach(function(a) { _simpanAngkatanInternal(a); });

    return {
      success: true,
      message: '✓ Berhasil menambahkan ' + rowsToAdd.length + ' siswa sekaligus!'
    };
  } catch (e) {
    return { success: false, message: 'Gagal menambah siswa secara masal: ' + e.toString() };
  }
}

function hapusDataSiswa(token, rowIndex) {
  try {
    _requireEditAccess(token);

    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(SHEET_SISWA) || ss.insertSheet(SHEET_SISWA);
    const idx = Number(rowIndex);
    if (!idx || idx < 1 || idx > sheet.getLastRow()) {
      return { success: false, message: 'Baris siswa tidak valid.' };
    }
    const namaSiswa = sheet.getRange(idx, 1).getValue();
    sheet.deleteRow(idx);
    _catatLog(token, 'Hapus Siswa', namaSiswa + ' (baris #' + idx + ')');
    return { success: true, message: '✓ Data siswa berhasil dihapus.' };
  } catch (e) {
    return { success: false, message: 'Gagal menghapus data siswa: ' + e.toString() };
  }
}

// ============================================================
//  Hapus Siswa Secara Massal (Checklist Bulk Delete)
//  daftarRowIndex: array nomor baris sheet (hasil rowIndex dari getDataSiswaAdmin)
//  Baris dihapus dari nomor terbesar ke terkecil supaya index baris yang
//  belum dihapus tidak bergeser saat proses berlangsung.
// ============================================================
function hapusDataSiswaMassal(token, daftarRowIndex) {
  try {
    _requireEditAccess(token);

    if (!Array.isArray(daftarRowIndex) || daftarRowIndex.length === 0) {
      return { success: false, message: 'Pilih minimal satu siswa terlebih dahulu.' };
    }

    const data = _getSiswaSheetAndRows();
    const sheet = data.sheet;
    const validRows = new Set(data.values.map(function(row, i) { return data.startRow + i; }));

    // Urutkan descending & buang duplikat/baris tidak valid, agar deleteRow aman dipanggil berurutan.
    const rowsToDelete = Array.from(new Set(
      daftarRowIndex.map(function(r) { return Number(r); }).filter(function(idx) {
        return idx && validRows.has(idx);
      })
    )).sort(function(a, b) { return b - a; });

    if (rowsToDelete.length === 0) {
      return { success: false, message: 'Tidak ada baris valid yang bisa dihapus.' };
    }

    rowsToDelete.forEach(function(idx) {
      sheet.deleteRow(idx);
    });

    _catatLog(token, 'Hapus Massal Siswa', rowsToDelete.length + ' siswa dihapus sekaligus.');

    return {
      success: true,
      message: '✓ ' + rowsToDelete.length + ' siswa berhasil dihapus sekaligus.'
    };
  } catch (e) {
    return { success: false, message: 'Gagal menghapus siswa secara massal: ' + e.toString() };
  }
}

// ============================================================
//  Set Angkatan Secara Massal (Checklist Bulk Assign)
//  daftarRowIndex: array nomor baris sheet (hasil rowIndex dari getDataSiswaAdmin)
//  angkatanBaru:   nilai angkatan yang akan diterapkan ke seluruh baris terpilih
// ============================================================
function setAngkatanMassal(token, daftarRowIndex, angkatanBaru) {
  try {
    _requireEditAccess(token);

    const value = String(angkatanBaru || '').trim();
    if (!value) return { success: false, message: 'Angkatan tujuan wajib dipilih.' };
    if (!Array.isArray(daftarRowIndex) || daftarRowIndex.length === 0) {
      return { success: false, message: 'Pilih minimal satu siswa terlebih dahulu.' };
    }

    const data = _getSiswaSheetAndRows();
    const sheet = data.sheet;
    const validRows = new Set(data.values.map(function(row, i) { return data.startRow + i; }));

    let diperbarui = 0;
    daftarRowIndex.forEach(function(rIdx) {
      const idx = Number(rIdx);
      if (idx && validRows.has(idx)) {
        sheet.getRange(idx, 3).setValue(value);
        diperbarui++;
      }
    });

    if (diperbarui === 0) {
      return { success: false, message: 'Tidak ada baris valid yang diperbarui.' };
    }

    _simpanAngkatanInternal(value);
    _catatLog(token, 'Set Angkatan Massal', diperbarui + ' siswa -> Angkatan "' + value + '"');
    return {
      success: true,
      message: '✓ Angkatan "' + value + '" berhasil diterapkan ke ' + diperbarui + ' siswa.'
    };
  } catch (e) {
    return { success: false, message: 'Gagal menerapkan angkatan massal: ' + e.toString() };
  }
}

// ============================================================
//  Set Status Siswa (Satuan & Massal)
//  Status yang didukung: AKTIF, LULUS, PINDAH
// ============================================================
const STATUS_SISWA_VALID = ['AKTIF', 'LULUS', 'PINDAH'];

function setStatusSiswa(token, rowIndex, statusBaru) {
  try {
    _requireEditAccess(token);

    const idx = Number(rowIndex);
    const value = String(statusBaru || '').trim().toUpperCase();
    if (!idx || idx < 1) return { success: false, message: 'Baris siswa tidak valid.' };
    if (STATUS_SISWA_VALID.indexOf(value) === -1) {
      return { success: false, message: 'Status tidak dikenali. Gunakan AKTIF, LULUS, atau PINDAH.' };
    }

    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(SHEET_SISWA) || ss.insertSheet(SHEET_SISWA);
    if (idx > sheet.getLastRow()) return { success: false, message: 'Baris siswa tidak ditemukan.' };

    sheet.getRange(idx, 4).setValue(value);
    _catatLog(token, 'Ubah Status Siswa', 'Baris #' + idx + ' -> ' + value);
    return { success: true, message: '✓ Status siswa diperbarui menjadi ' + value + '.' };
  } catch (e) {
    return { success: false, message: 'Gagal memperbarui status: ' + e.toString() };
  }
}

function setStatusMassal(token, daftarRowIndex, statusBaru) {
  try {
    _requireEditAccess(token);

    const value = String(statusBaru || '').trim().toUpperCase();
    if (STATUS_SISWA_VALID.indexOf(value) === -1) {
      return { success: false, message: 'Status tidak dikenali. Gunakan AKTIF, LULUS, atau PINDAH.' };
    }
    if (!Array.isArray(daftarRowIndex) || daftarRowIndex.length === 0) {
      return { success: false, message: 'Pilih minimal satu siswa terlebih dahulu.' };
    }

    const data = _getSiswaSheetAndRows();
    const sheet = data.sheet;
    const validRows = new Set(data.values.map(function(row, i) { return data.startRow + i; }));

    let diperbarui = 0;
    daftarRowIndex.forEach(function(rIdx) {
      const idx = Number(rIdx);
      if (idx && validRows.has(idx)) {
        sheet.getRange(idx, 4).setValue(value);
        diperbarui++;
      }
    });

    if (diperbarui === 0) {
      return { success: false, message: 'Tidak ada baris valid yang diperbarui.' };
    }

    _catatLog(token, 'Ubah Status Massal Siswa', diperbarui + ' siswa -> ' + value);
    return {
      success: true,
      message: '✓ Status "' + value + '" diterapkan ke ' + diperbarui + ' siswa.'
    };
  } catch (e) {
    return { success: false, message: 'Gagal memperbarui status massal: ' + e.toString() };
  }
}

// ============================================================
//  Helper: Upload satu file (base64) ke subfolder Drive target.
//  subfolderName: "Foto Bukti Kejadian" atau "Foto Surat Pernyataan".
//  Mengembalikan { url, hardFail, message }.
//  hardFail=true artinya file ditolak (tipe/ukuran tidak valid) -> jangan simpan baris.
//  hardFail=false & url berisi "Upload gagal: ..." artinya upload gagal saat proses,
//  namun baris tetap disimpan (perilaku lama tetap dipertahankan).
// ============================================================
function _uploadFotoBase64(fileData, fileName, subfolderName) {
  if (!fileData || !fileName) return { url: "-", hardFail: false };
  try {
    const contentType = fileData.substring(5, fileData.indexOf(';'));

    if (!(contentType.indexOf('image/') === 0 || contentType === 'application/pdf')) {
      return { url: '-', hardFail: true, message: 'Tipe file tidak diizinkan.' };
    }

    const folder     = _getOrCreateSubfolder(subfolderName || 'Foto Bukti Kejadian');
    const base64Data = fileData.split(',')[1];
    const bytes      = Utilities.base64Decode(base64Data);

    if (bytes.length > 10 * 1024 * 1024) {
      return { url: '-', hardFail: true, message: 'Ukuran file melebihi 10MB.' };
    }

    const blob = Utilities.newBlob(bytes, contentType, fileName);
    const file = folder.createFile(blob);

    try {
      file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);
    } catch (shareErr) {
      console.warn('Set sharing error:', shareErr);
    }
    return { url: file.getUrl(), hardFail: false };
  } catch (uploadErr) {
    console.error('Upload error:', uploadErr);
    return { url: 'Upload gagal: ' + (uploadErr.message || uploadErr.toString()), hardFail: false };
  }
}

// ============================================================
//  MANAJEMEN DATA WALI KELAS (Kelas, Nama, No. WA)
//  Dikelola sepenuhnya lewat web (tab Admin, khusus Superadmin) —
//  tidak perlu edit sheet manual. Dipakai sebagai sumber nomor tujuan
//  saat mengirim notifikasi WhatsApp (lihat _getWaliKelas / bagian
//  NOTIFIKASI WHATSAPP di bawah).
// ============================================================
function _isWaliHeaderRow(row) {
  const nilai = [row[0], row[1]].map(function(v) {
    return String(v || '').trim().toLowerCase();
  });
  return nilai[0] === 'kelas' && nilai[1].indexOf('nama') === 0;
}

function _getWaliKelasSheetAndRows() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEET_WALI) || ss.insertSheet(SHEET_WALI);
  const range = sheet.getDataRange();
  const values = range.getDisplayValues();

  if (!values || values.length === 0) {
    return { sheet: sheet, startRow: 1, values: [] };
  }

  const startRow = _isWaliHeaderRow(values[0]) ? 2 : 1;
  const filteredValues = values.slice(startRow - 1);
  return { sheet: sheet, startRow: startRow, values: filteredValues };
}

function _getAllWaliKelasRecords() {
  const data = _getWaliKelasSheetAndRows();
  return data.values
    .map(function(row, index) {
      return {
        rowIndex: data.startRow + index,
        kelas: String(row[0] || '').trim(),
        nama: String(row[1] || '').trim(),
        noWA: String(row[2] || '').trim()
      };
    })
    .filter(function(item) {
      return item.kelas !== '';
    });
}

// Entry point dipanggil dari tab Admin (Superadmin) untuk menampilkan
// daftar wali kelas yang sudah terdaftar.
function getDataWaliKelasAdmin(token) {
  try {
    _requireRole(token, ['superadmin']);
    return _getAllWaliKelasRecords();
  } catch (e) {
    console.error('getDataWaliKelasAdmin error:', e);
    return [];
  }
}

// Tambah / edit satu data wali kelas. Kalau rowIndex diisi -> update baris
// itu, kalau kosong -> tambah baris baru. Satu kelas hanya boleh punya satu
// entri (dicegah duplikat, kecuali saat mengedit baris itu sendiri).
function simpanWaliKelas(token, dataWali) {
  try {
    _requireRole(token, ['superadmin']);

    const kelas = String((dataWali && dataWali.kelas) || '').trim();
    const nama = String((dataWali && dataWali.nama) || '').trim();
    const noWARaw = String((dataWali && dataWali.noWA) || '').trim();

    if (!kelas || !nama || !noWARaw) {
      return { success: false, message: 'Kelas, nama wali kelas, dan nomor WA wajib diisi.' };
    }

    const noWA = _formatNomorWA(noWARaw);
    if (!noWA || noWA.length < 10 || noWA.length > 15) {
      return { success: false, message: 'Nomor WhatsApp tidak valid. Gunakan format 08xxxxxxxxxx atau 62xxxxxxxxxx.' };
    }

    const data = _getWaliKelasSheetAndRows();
    const sheet = data.sheet;
    const rowIndex = Number(dataWali && dataWali.rowIndex);

    // Cek duplikat nama kelas (case-insensitive), kecuali baris yang sedang diedit.
    const existing = _getAllWaliKelasRecords();
    const duplikat = existing.find(function(item) {
      return item.kelas.toUpperCase() === kelas.toUpperCase() && item.rowIndex !== rowIndex;
    });
    if (duplikat) {
      return { success: false, message: 'Kelas "' + kelas + '" sudah punya data wali kelas (baris #' + duplikat.rowIndex + '). Edit data yang sudah ada, jangan buat duplikat.' };
    }

    if (rowIndex && rowIndex > 0) {
      sheet.getRange(rowIndex, 1, 1, 3).setValues([[kelas, nama, noWA]]);
      _catatLog(token, 'Edit Wali Kelas', kelas + ' - ' + nama + ' - ' + noWA);
      return { success: true, message: '✓ Data wali kelas berhasil diperbarui.' };
    }

    if (sheet.getLastRow() === 0) {
      sheet.appendRow(['Kelas', 'Nama Wali Kelas', 'No. WhatsApp']);
      sheet.getRange(1, 1, 1, 3).setFontWeight('bold').setBackground('#1e293b').setFontColor('#ffffff');
    }
    sheet.appendRow([kelas, nama, noWA]);
    _catatLog(token, 'Tambah Wali Kelas', kelas + ' - ' + nama + ' - ' + noWA);
    return { success: true, message: '✓ Data wali kelas berhasil ditambahkan.' };
  } catch (e) {
    return { success: false, message: 'Gagal menyimpan data wali kelas: ' + e.toString() };
  }
}

function hapusWaliKelas(token, rowIndex) {
  try {
    _requireRole(token, ['superadmin']);

    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(SHEET_WALI) || ss.insertSheet(SHEET_WALI);
    const idx = Number(rowIndex);
    if (!idx || idx < 1 || idx > sheet.getLastRow()) {
      return { success: false, message: 'Baris wali kelas tidak valid.' };
    }
    const kelas = sheet.getRange(idx, 1).getValue();
    const nama = sheet.getRange(idx, 2).getValue();
    sheet.deleteRow(idx);
    _catatLog(token, 'Hapus Wali Kelas', kelas + ' - ' + nama + ' (baris #' + idx + ')');
    return { success: true, message: '✓ Data wali kelas berhasil dihapus.' };
  } catch (e) {
    return { success: false, message: 'Gagal menghapus data wali kelas: ' + e.toString() };
  }
}

// ============================================================
//  NOTIFIKASI WHATSAPP (FONNTE)
//  Dipicu manual lewat checkbox "Kirim notifikasi WA?" saat BK/Admin
//  mengisi form laporan kejadian. Dikirim ke nomor WA wali kelas yang
//  bersangkutan (data diambil dari sheet "WaliKelas", dikelola lewat
//  tab Admin > Data Wali Kelas oleh Superadmin).
// ============================================================

// Jalankan fungsi ini SEKALI dari Editor Apps Script (bukan dari web app)
// untuk menyimpan token Fonnte dengan aman ke Script Properties.
// Cara pakai: ganti 'TOKEN_ANDA_DISINI' dengan token asli dari dashboard
// Fonnte, lalu klik Run pada fungsi ini di Editor Apps Script.
function setFonnteToken() {
  const token = 'Veapqku9XUf4Cj7TNCfk'; // <-- ganti dengan token Fonnte asli
  if (!token || token === 'Veapqku9XUf4Cj7TNCfk') {
    throw new Error('Ganti dulu TOKEN_ANDA_DISINI dengan token Fonnte yang asli sebelum menjalankan fungsi ini.');
  }
  PropertiesService.getScriptProperties().setProperty('FONNTE_TOKEN', token);
  Logger.log('✓ Token Fonnte berhasil disimpan.');
}

// Jalankan fungsi ini SEKALI dari Editor Apps Script (bukan dari web app)
// untuk: (1) memicu popup izin akses internet (UrlFetchApp) yang wajib
// disetujui sebelum notifikasi WA bisa jalan dari web app, dan (2) untuk
// mengetes apakah token & nomor WA sudah benar sebelum dipakai sungguhan.
// Ganti nomor di bawah dengan nomor WA aktifmu sendiri untuk tes.
function testKirimWA() {
  const nomorTes = '085156209404'; // <-- ganti dengan nomor WA aktif untuk tes
  if (!nomorTes || nomorTes.indexOf('x') !== -1) {
    throw new Error('Ganti dulu nomorTes dengan nomor WA aktifmu sebelum menjalankan fungsi ini.');
  }
  const hasil = _kirimWhatsAppFonnte(_formatNomorWA(nomorTes), 'Tes notifikasi dari Sistem BK Digital ✅');
  Logger.log(JSON.stringify(hasil));
  if (!hasil.success) {
    throw new Error('Gagal kirim WA tes: ' + hasil.message);
  }
  Logger.log('✓ WA tes berhasil terkirim ke ' + nomorTes);
}

function _getFonnteToken() {
  return PropertiesService.getScriptProperties().getProperty('FONNTE_TOKEN') || '';
}

// Normalisasi nomor WA Indonesia ke format 62xxxxxxxxxx (tanpa spasi/strip/+).
function _formatNomorWA(nomor) {
  let n = String(nomor || '').replace(/[^0-9]/g, '');
  if (!n) return '';
  if (n.charAt(0) === '0') {
    n = '62' + n.substring(1);
  } else if (n.substring(0, 2) !== '62') {
    n = '62' + n;
  }
  return n;
}

// Ambil nomor WA & nama wali kelas untuk kelas tertentu (dipakai internal
// oleh notifikasi). Pencarian tidak case-sensitive dan mengabaikan spasi berlebih.
function _getWaliKelas(kelas) {
  const kelasTarget = String(kelas || '').trim().toUpperCase();
  if (!kelasTarget) return null;

  const record = _getAllWaliKelasRecords().find(function(item) {
    return item.kelas.toUpperCase() === kelasTarget;
  });
  if (!record) return null;

  return {
    kelas: record.kelas,
    nama: record.nama,
    noWA: _formatNomorWA(record.noWA)
  };
}

// Kirim satu pesan WhatsApp lewat Fonnte. Mengembalikan { success, message }.
// Tidak pernah melempar error ke pemanggil — kegagalan kirim WA tidak boleh
// menggagalkan penyimpanan laporan.
function _kirimWhatsAppFonnte(nomorTujuan, pesan) {
  const token = _getFonnteToken();
  if (!token) {
    return { success: false, message: 'Token Fonnte belum diset. Jalankan fungsi setFonnteToken() dari Editor Apps Script.' };
  }
  if (!nomorTujuan) {
    return { success: false, message: 'Nomor WA tujuan kosong.' };
  }

  try {
    const response = UrlFetchApp.fetch(FONNTE_SEND_URL, {
      method: 'post',
      headers: { Authorization: token },
      payload: {
        target: nomorTujuan,
        message: pesan,
        countryCode: '62'
      },
      muteHttpExceptions: true
    });

    const result = JSON.parse(response.getContentText());
    if (result && result.status) {
      return { success: true, message: 'Terkirim' };
    }
    return { success: false, message: (result && (result.reason || result.detail)) || 'Gagal mengirim (respons tidak dikenali).' };
  } catch (e) {
    return { success: false, message: 'Gagal mengirim WA: ' + e.toString() };
  }
}

// Bangun & kirim notifikasi WA ke wali kelas untuk setiap kelas yang
// terlibat dalam satu laporan (satu laporan bisa berisi siswa dari
// beberapa kelas berbeda). Dipanggil dari simpanData() saat checkbox
// "Kirim notifikasi WA?" dicentang.
// Mengembalikan array ringkasan pengiriman per kelas untuk dicatat ke log.
function _notifikasiWaliKelas(dataForm) {
  const ringkasan = [];

  // Kelompokkan nama siswa per kelas (satu laporan bisa multi-siswa/multi-kelas).
  const perKelas = {};
  dataForm.daftarSiswa.forEach(function(item) {
    const kelas = String(item.kelas || '').trim();
    if (!kelas) return;
    if (!perKelas[kelas]) perKelas[kelas] = [];
    perKelas[kelas].push(item.nama);
  });

  Object.keys(perKelas).forEach(function(kelas) {
    const waliInfo = _getWaliKelas(kelas);
    if (!waliInfo || !waliInfo.noWA) {
      ringkasan.push(kelas + ': gagal (data wali kelas/nomor WA tidak ditemukan)');
      return;
    }

    const namaSiswa = perKelas[kelas].join(', ');
    const pesan =
      '*Notifikasi RUANG BK - ' + kelas + '*\n\n' +
      'Yth. ' + waliInfo.nama + ',\n\n' +
      'Terdapat laporan kejadian baru untuk siswa berikut:\n' +
      'Nama: ' + namaSiswa + '\n' +
      'Kelas: ' + kelas + '\n' +
      'Tanggal Kejadian: ' + dataForm.tglKejadian + '\n' +
      'Kategori: ' + (dataForm.kategori || '-') + '\n' +
      'Kasus/Keterangan: ' + dataForm.kasus + '\n' +
      'Tindakan: ' + dataForm.tindakan + '\n\n' +
      'Mohon perhatian dan tindak lanjutnya. Terima kasih.\n' +
      '(Pesan otomatis dari Sistem BK Digital)';

    const hasil = _kirimWhatsAppFonnte(waliInfo.noWA, pesan);
    ringkasan.push(kelas + ' (' + waliInfo.nama + '): ' + (hasil.success ? 'terkirim' : 'gagal - ' + hasil.message));
  });

  return ringkasan;
}

function simpanData(dataForm, token) {
  try {
    const ss    = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(SHEET_DATA) || ss.getSheets()[0];
    
    _ensureHeader(sheet);

    // Foto bukti kejadian: satu file, dipakai bersama untuk seluruh baris laporan ini
    // (karena biasanya cuma satu foto kejadian, bukan per-siswa).
    let fileUrl = "-";
    if (dataForm.fileData && dataForm.fileName) {
      const hasil = _uploadFotoBase64(dataForm.fileData, dataForm.fileName, 'Foto Bukti Kejadian');
      if (hasil.hardFail) return { success: false, message: hasil.message };
      fileUrl = hasil.url;
    }

    const timestamp = new Date();
    for (let idx = 0; idx < dataForm.daftarSiswa.length; idx++) {
      const item = dataForm.daftarSiswa[idx];

      // Foto surat pernyataan: individual per siswa, karena tiap siswa yang terlibat
      // bisa punya surat pernyataannya masing-masing (nama & isi berbeda-beda).
      let suratUrl = "-";
      if (item.suratFileData && item.suratFileName) {
        const namaFileUnik = item.nama + ' - ' + item.suratFileName;
        const hasilSurat = _uploadFotoBase64(item.suratFileData, namaFileUnik, 'Foto Surat Pernyataan');
        if (hasilSurat.hardFail) {
          return { success: false, message: 'Surat pernyataan ' + item.nama + ': ' + hasilSurat.message };
        }
        suratUrl = hasilSurat.url;
      }

      sheet.appendRow([
        timestamp,                   // Col 1: Timestamp
        dataForm.tglKejadian,        // Col 2: Tanggal Kejadian
        item.nama,                   // Col 3: Nama Siswa
        item.kelas,                  // Col 4: Kelas Saat Kejadian
        item.angkatan || '',         // Col 5: Angkatan/Tahun Ajaran
        dataForm.kategori || '-',    // Col 6: Kategori
        dataForm.kasus,              // Col 7: Kasus / Prestasi
        dataForm.tindakan,           // Col 8: Tindakan
        fileUrl,                     // Col 9: URL Bukti (foto kejadian, shared)
        suratUrl                     // Col 10: URL Surat Pernyataan (per siswa)
      ]);
    }

    // Catat ke Log Aktivitas: prioritas identitas -> (1) user yang sedang login lewat
    // sesi (kalau BK login duluan sebelum isi form), (2) nama yang diketik manual di
    // kolom "Dicatat oleh", (3) kalau dua-duanya kosong -> "Pengunjung (belum login)".
    const usernameLogin = _getUsernameFromToken(token);
    const roleLogin = _getRoleFromToken(token);
    // Device: kalau sudah login pakai device yang tercatat di sesi; kalau
    // pengunjung tanpa login, pakai device yang dikirim langsung dari client
    // (lihat dataForm.deviceInfo, diisi getDeviceInfo() di index.html).
    const deviceLogin = _getDeviceFromToken(token) || String((dataForm && dataForm.deviceInfo) || '').trim().slice(0, 150) || 'Tidak diketahui';
    const namaDiketik = String((dataForm && dataForm.dicatatOleh) || '').trim();

    let logUsername, logRole;
    if (usernameLogin) {
      logUsername = usernameLogin;
      logRole = roleLogin || '-';
    } else if (namaDiketik) {
      logUsername = namaDiketik;
      logRole = 'Pengunjung (nama manual)';
    } else {
      logUsername = '-';
      logRole = 'Pengunjung (belum login)';
    }

    const namaSiswaLog = dataForm.daftarSiswa.map(function(s) { return s.nama; }).join(', ');
    _appendLogRow(logUsername, logRole, 'Tambah Laporan', dataForm.daftarSiswa.length + ' siswa (' + namaSiswaLog + ') - "' + dataForm.kasus + '"', deviceLogin);

    // Notifikasi WhatsApp ke wali kelas — hanya jika dicentang di form DAN
    // toggle notifikasi WA untuk peran pengirim laporan sedang AKTIF
    // (diatur Superadmin di tab Admin Siswa: user/pengunjung, admin, superadmin).
    let infoWA = '';
    if (dataForm.kirimNotifikasiWA) {
      const peranPengirim = roleLogin || 'user'; // belum login (roleLogin kosong) = peran "user"/pengunjung
      if (_isWaNotifEnabledForRole(peranPengirim)) {
        const ringkasanWA = _notifikasiWaliKelas(dataForm);
        if (ringkasanWA.length > 0) {
          _appendLogRow(logUsername, logRole, 'Notifikasi WA Wali Kelas', ringkasanWA.join(' | '), deviceLogin);
          infoWA = ' WA: ' + ringkasanWA.join(', ');
        }
      } else {
        _appendLogRow(logUsername, logRole, 'Notifikasi WA Dilewati', 'Toggle notifikasi WA untuk peran ini sedang dinonaktifkan oleh Superadmin.', deviceLogin);
        infoWA = ' (Notifikasi WA dilewati: dinonaktifkan Superadmin untuk peran ini.)';
      }
    }

    return {
      success: true,
      message: "✓ Berhasil menyimpan " + dataForm.daftarSiswa.length + " data laporan siswa!" + infoWA
    };
  } catch (error) {
    return { success: false, message: "Gagal menyimpan: " + error.toString() };
  }
}

// ============================================================
//  Dashboard Ringkasan — Kartu Statistik di Tab Input Data
//  Dihitung di server (bukan kirim semua rawData ke browser) supaya
//  ringan. Berbasis "Tgl Kejadian" (bukan Timestamp submit) untuk
//  filter "bulan ini", konsisten dengan cara Grafik Tren membaca data.
// ============================================================
function getDashboardStats(token) {
  try {
    _requireRole(token, ['admin', 'superadmin']);

    const ss    = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(SHEET_DATA) || ss.getSheets()[0];
    if (sheet.getLastRow() < 2) {
      return {
        totalLaporanBulanIni: 0, totalPelanggaranBulanIni: 0, totalPrestasiBulanIni: 0,
        kelasPalingBanyakKasus: null, siswaPelanggaranTerbanyak: null, siswaPrestasiTerbanyak: null,
        totalLaporanKeseluruhan: 0
      };
    }

    const values = sheet.getRange(2, 1, sheet.getLastRow() - 1, Math.max(8, sheet.getLastColumn())).getValues();
    const now = new Date();
    const bulanIni = now.getMonth();
    const tahunIni = now.getFullYear();

    let totalLaporanBulanIni = 0;
    let totalPelanggaranBulanIni = 0;
    let totalPrestasiBulanIni = 0;
    const kelasCount = {};       // kelas -> jumlah kasus/pelanggaran bulan ini
    const siswaPelanggaran = {}; // nama -> jumlah pelanggaran bulan ini
    const siswaPrestasi = {};    // nama -> jumlah prestasi (keseluruhan)

    values.forEach(function(row) {
      const tglKejadian = row[1];
      const nama = String(row[2] || '').trim();
      const kelas = String(row[3] || '').trim();
      const kategori = String(row[5] || '').trim();

      // Prestasi dihitung sepanjang waktu (bukan cuma bulan ini) supaya lebih
      // representatif sebagai "siswa berprestasi", tidak hilang tiap ganti bulan.
      if (kategori === 'Prestasi' && nama) {
        siswaPrestasi[nama] = (siswaPrestasi[nama] || 0) + 1;
      }

      let tgl = null;
      if (tglKejadian instanceof Date) {
        tgl = tglKejadian;
      } else if (tglKejadian) {
        const parsed = new Date(tglKejadian);
        if (!isNaN(parsed.getTime())) tgl = parsed;
      }
      if (!tgl || tgl.getMonth() !== bulanIni || tgl.getFullYear() !== tahunIni) return;

      totalLaporanBulanIni++;
      if (kategori === 'Pelanggaran' || kategori === 'Kasus') {
        totalPelanggaranBulanIni++;
        if (kelas) kelasCount[kelas] = (kelasCount[kelas] || 0) + 1;
        if (nama) siswaPelanggaran[nama] = (siswaPelanggaran[nama] || 0) + 1;
      } else if (kategori === 'Prestasi') {
        totalPrestasiBulanIni++;
      }
    });

    const topEntry = function(obj) {
      let topKey = null, topVal = 0;
      Object.keys(obj).forEach(function(k) {
        if (obj[k] > topVal) { topKey = k; topVal = obj[k]; }
      });
      return topKey ? { nama: topKey, jumlah: topVal } : null;
    };

    const kelasTop = topEntry(kelasCount);

    return {
      totalLaporanBulanIni: totalLaporanBulanIni,
      totalPelanggaranBulanIni: totalPelanggaranBulanIni,
      totalPrestasiBulanIni: totalPrestasiBulanIni,
      kelasPalingBanyakKasus: kelasTop ? { kelas: kelasTop.nama, jumlah: kelasTop.jumlah } : null,
      siswaPelanggaranTerbanyak: topEntry(siswaPelanggaran),
      siswaPrestasiTerbanyak: topEntry(siswaPrestasi),
      totalLaporanKeseluruhan: values.length
    };
  } catch (e) {
    console.error('getDashboardStats error:', e);
    throw e;
  }
}

function getRekapData(token) {
  try {
    _requireRole(token, ['admin', 'superadmin']);

    const ss    = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(SHEET_DATA) || ss.getSheets()[0];
    const range = sheet.getDataRange();
    const values = range.getDisplayValues();
    
    if (!values || values.length === 0) return [[]];
    return values;
  } catch (e) {
    console.error('getRekapData error:', e);
    throw e;
  }
}

function _ensureHeader(sheet) {
  if (sheet.getLastRow() === 0) {
    sheet.appendRow([
      "Timestamp", "Tgl Kejadian", "Nama Siswa", "Kelas",
      "Angkatan", "Kategori", "Kasus / Prestasi", "Tindakan", "URL Bukti", "URL Surat Pernyataan"
    ]);
    sheet.getRange(1, 1, 1, 10).setFontWeight('bold').setBackground('#1e293b').setFontColor('#ffffff');
    return;
  }

  // Migrasi: tambahkan kolom URL Surat Pernyataan jika sheet lama belum punya kolom ke-10
  const lastCol = Math.max(10, sheet.getLastColumn());
  const header = sheet.getRange(1, 1, 1, lastCol).getValues()[0];
  if (String(header[9] || '').trim().toLowerCase() !== 'url surat pernyataan') {
    sheet.getRange(1, 10).setValue('URL Surat Pernyataan')
      .setFontWeight('bold').setBackground('#1e293b').setFontColor('#ffffff');
  }
}

// ============================================================
//  Edit Field Bersama untuk Satu Kelompok Kejadian
//  Dipakai saat user meng-edit satu laporan yang merupakan bagian dari
//  kejadian yang diinput bersamaan (banyak siswa, 1 kasus yang sama) —
//  supaya field yang memang sama untuk semua siswa (Tanggal, Kategori,
//  Kasus, Tindakan) bisa diubah sekali klik untuk semua baris terkait,
//  tanpa perlu edit satu-satu. Nama/Kelas/Angkatan/foto tiap siswa TIDAK
//  ikut berubah karena itu memang unik per siswa.
//  daftarRowIndex: array rowIndex (index rawData) baris-baris lain dalam
//  kelompok yang sama (TIDAK termasuk baris utama yang sudah diedit lewat editData).
// ============================================================
function editSharedKelompok(token, daftarRowIndex, sharedData) {
  try {
    _requireEditAccess(token);

    if (!Array.isArray(daftarRowIndex) || daftarRowIndex.length === 0) {
      return { success: false, message: 'Tidak ada baris kelompok yang perlu diperbarui.' };
    }

    const ss    = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(SHEET_DATA) || ss.getSheets()[0];
    const lastRow = sheet.getLastRow();

    const tglKejadian = sharedData && sharedData.tglKejadian;
    const kategori    = sharedData && sharedData.kategori;
    const kasus       = sharedData && sharedData.kasus;
    const tindakan    = sharedData && sharedData.tindakan;

    let jumlahDiperbarui = 0;
    daftarRowIndex.forEach(function(rowIndex) {
      const sheetRow = Number(rowIndex) + 1;
      if (sheetRow < 2 || sheetRow > lastRow) return;

      if (tglKejadian) sheet.getRange(sheetRow, 2).setValue(tglKejadian);
      if (kategori)    sheet.getRange(sheetRow, 6).setValue(kategori);
      if (kasus)        sheet.getRange(sheetRow, 7).setValue(kasus);
      if (tindakan)     sheet.getRange(sheetRow, 8).setValue(tindakan);
      jumlahDiperbarui++;
    });

    _catatLog(token, 'Edit Laporan (Grup)', (jumlahDiperbarui + 1) + ' baris - "' + (kasus || '') + '"');

    return {
      success: true,
      message: '✓ ' + (jumlahDiperbarui + 1) + ' laporan dalam kejadian yang sama berhasil diperbarui sekaligus!'
    };
  } catch (e) {
    return { success: false, message: 'Gagal memperbarui kelompok laporan: ' + e.toString() };
  }
}

function editData(token, dataEdit) {
  try {
    _requireEditAccess(token);

    const ss    = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(SHEET_DATA) || ss.getSheets()[0];
    const sheetRow = dataEdit.rowIndex + 1;

    if (sheetRow < 2 || sheetRow > sheet.getLastRow()) {
      return { success: false, message: "Baris tidak valid." };
    }

    _ensureHeader(sheet);

    const lastCol = sheet.getLastColumn();
    let fileUrl  = lastCol >= 9 ? sheet.getRange(sheetRow, 9).getValue() : sheet.getRange(sheetRow, 8).getValue();
    let suratUrl = lastCol >= 10 ? (sheet.getRange(sheetRow, 10).getValue() || '-') : '-';

    if (dataEdit.fileData && dataEdit.fileName) {
      const hasil = _uploadFotoBase64(dataEdit.fileData, dataEdit.fileName, 'Foto Bukti Kejadian');
      if (!hasil.hardFail) fileUrl = hasil.url;
    }

    if (dataEdit.suratFileData && dataEdit.suratFileName) {
      const hasilSurat = _uploadFotoBase64(dataEdit.suratFileData, dataEdit.suratFileName, 'Foto Surat Pernyataan');
      if (!hasilSurat.hardFail) suratUrl = hasilSurat.url;
    }

    sheet.getRange(sheetRow, 2).setValue(dataEdit.tglKejadian);
    sheet.getRange(sheetRow, 3).setValue(dataEdit.nama);
    sheet.getRange(sheetRow, 4).setValue(dataEdit.kelas);
    sheet.getRange(sheetRow, 5).setValue(dataEdit.angkatan || '');
    sheet.getRange(sheetRow, 6).setValue(dataEdit.kategori);
    sheet.getRange(sheetRow, 7).setValue(dataEdit.kasus);
    sheet.getRange(sheetRow, 8).setValue(dataEdit.tindakan);
    sheet.getRange(sheetRow, 9).setValue(fileUrl);
    sheet.getRange(sheetRow, 10).setValue(suratUrl);

    _catatLog(token, 'Edit Laporan', 'Baris #' + dataEdit.rowIndex + ' - ' + dataEdit.nama + ' (' + dataEdit.kelas + ') - "' + dataEdit.kasus + '"');

    return { success: true, message: "✓ Data berhasil diperbarui!" };
  } catch (e) {
    return { success: false, message: "Gagal mengedit: " + e.toString() };
  }
}

// Mengekstrak Drive file ID dari URL hasil file.getUrl(), lalu memindahkannya
// ke Trash. Aman dipanggil dengan URL kosong/bukan link Drive — tidak melempar error
// ke pemanggil (delete data tetap lanjut walau file gagal dihapus).
function _hapusFileDriveDariUrl(url) {
  if (!url || typeof url !== 'string') return;
  const str = url.trim();
  if (!str || str === '-' || str.toLowerCase().indexOf('gagal') !== -1) return;

  let fileId = null;
  let m = str.match(/\/d\/([a-zA-Z0-9_-]+)/);
  if (m) {
    fileId = m[1];
  } else {
    m = str.match(/[?&]id=([a-zA-Z0-9_-]+)/);
    if (m) fileId = m[1];
  }
  if (!fileId) return;

  try {
    DriveApp.getFileById(fileId).setTrashed(true);
  } catch (e) {
    console.warn('Gagal menghapus file Drive (' + fileId + '):', e);
  }
}

function hapusData(token, rowIndex) {
  try {
    _requireEditAccess(token);

    const ss    = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(SHEET_DATA) || ss.getSheets()[0];
    const sheetRow = rowIndex + 1;

    if (sheetRow < 2 || sheetRow > sheet.getLastRow()) {
      return { success: false, message: "Baris tidak valid." };
    }

    // Ambil URL bukti & surat sebelum baris dihapus, supaya file terkait
    // di Google Drive ikut dihapus (dipindah ke Trash) juga.
    const lastCol = Math.max(10, sheet.getLastColumn());
    const rowValues = sheet.getRange(sheetRow, 1, 1, lastCol).getValues()[0];
    const urlBukti = rowValues[8];  // Col 9: URL Bukti
    const urlSurat = rowValues[9];  // Col 10: URL Surat Pernyataan
    const namaSiswa = rowValues[2];
    const kasusSiswa = rowValues[6];

    sheet.deleteRow(sheetRow);

    _hapusFileDriveDariUrl(urlBukti);
    _hapusFileDriveDariUrl(urlSurat);

    _catatLog(token, 'Hapus Laporan', 'Baris #' + rowIndex + ' - ' + namaSiswa + ' - "' + kasusSiswa + '"');

    return { success: true, message: "✓ Data & file terkait berhasil dihapus!" };
  } catch (e) {
    return { success: false, message: "Gagal menghapus: " + e.toString() };
  }
}

// ============================================================
//  Hapus Laporan Secara Massal (Checklist Bulk Delete di Rekap Laporan)
//  daftarRowIndex: array nilai rowIndex (index rawData, sama seperti dipakai
//  hapusData) hasil checklist di tabel Rekap Laporan.
//  Baris & file Drive terkaitnya dihapus dari nomor terbesar ke terkecil
//  supaya index baris yang belum diproses tidak bergeser.
// ============================================================
function hapusDataMassal(token, daftarRowIndex) {
  try {
    _requireEditAccess(token);

    if (!Array.isArray(daftarRowIndex) || daftarRowIndex.length === 0) {
      return { success: false, message: 'Pilih minimal satu laporan terlebih dahulu.' };
    }

    const ss    = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(SHEET_DATA) || ss.getSheets()[0];
    const lastRow = sheet.getLastRow();
    const lastCol = Math.max(10, sheet.getLastColumn());

    // rowIndex -> sheetRow (rowIndex + 1), validasi & urutkan descending
    // supaya deleteRow aman dipanggil berurutan tanpa menggeser baris lain
    // yang belum diproses.
    const sheetRows = Array.from(new Set(
      daftarRowIndex.map(function(r) { return Number(r) + 1; }).filter(function(sheetRow) {
        return sheetRow >= 2 && sheetRow <= lastRow;
      })
    )).sort(function(a, b) { return b - a; });

    if (sheetRows.length === 0) {
      return { success: false, message: 'Tidak ada baris valid yang bisa dihapus.' };
    }

    sheetRows.forEach(function(sheetRow) {
      const rowValues = sheet.getRange(sheetRow, 1, 1, lastCol).getValues()[0];
      const urlBukti = rowValues[8];
      const urlSurat = rowValues[9];

      sheet.deleteRow(sheetRow);

      _hapusFileDriveDariUrl(urlBukti);
      _hapusFileDriveDariUrl(urlSurat);
    });

    _catatLog(token, 'Hapus Massal Laporan', sheetRows.length + ' baris dihapus sekaligus.');

    return {
      success: true,
      message: '✓ ' + sheetRows.length + ' laporan & file bukti terkait berhasil dihapus sekaligus.'
    };
  } catch (e) {
    return { success: false, message: 'Gagal menghapus laporan secara massal: ' + e.toString() };
  }
}

// ============================================================
//  Edit Laporan Secara Massal (Checklist Bulk Edit di Rekap Laporan)
//  daftarRowIndex: array nilai rowIndex (index rawData, sama seperti hapusData).
//  perubahan: { kategori?: string, tindakan?: string } — field yang tidak
//  disertakan/kosong TIDAK diubah, hanya field yang diisi yang diterapkan
//  ke semua baris terpilih.
// ============================================================
function editDataMassal(token, daftarRowIndex, perubahan) {
  try {
    _requireEditAccess(token);

    if (!Array.isArray(daftarRowIndex) || daftarRowIndex.length === 0) {
      return { success: false, message: 'Pilih minimal satu laporan terlebih dahulu.' };
    }

    const kategoriBaru = String((perubahan && perubahan.kategori) || '').trim();
    const tindakanBaru = String((perubahan && perubahan.tindakan) || '').trim();

    if (!kategoriBaru && !tindakanBaru) {
      return { success: false, message: 'Isi minimal salah satu field (Kategori atau Tindakan) yang ingin diterapkan.' };
    }

    const ss    = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(SHEET_DATA) || ss.getSheets()[0];
    const lastRow = sheet.getLastRow();

    const sheetRows = Array.from(new Set(
      daftarRowIndex.map(function(r) { return Number(r) + 1; }).filter(function(sheetRow) {
        return sheetRow >= 2 && sheetRow <= lastRow;
      })
    ));

    if (sheetRows.length === 0) {
      return { success: false, message: 'Tidak ada baris valid yang bisa diperbarui.' };
    }

    sheetRows.forEach(function(sheetRow) {
      if (kategoriBaru) sheet.getRange(sheetRow, 6).setValue(kategoriBaru);  // Col 6: Kategori
      if (tindakanBaru) sheet.getRange(sheetRow, 8).setValue(tindakanBaru);  // Col 8: Tindakan
    });

    _catatLog(token, 'Edit Massal Laporan', sheetRows.length + ' baris - Kategori: "' + (kategoriBaru || '(tidak diubah)') + '", Tindakan: "' + (tindakanBaru || '(tidak diubah)') + '"');

    return {
      success: true,
      message: '✓ ' + sheetRows.length + ' laporan berhasil diperbarui sekaligus.'
    };
  } catch (e) {
    return { success: false, message: 'Gagal mengedit laporan secara massal: ' + e.toString() };
  }
}