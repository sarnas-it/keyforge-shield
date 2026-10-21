// keyforge-shield / core — OPEN SOURCE (Apache-2.0)
//
// Референсная реализация протокола верификации. В проде `verify_strings`
// заменяется на реальную проверку Ed25519-подписанного токена; здесь —
// упрощённый стенд для прототипа (сравнение двух C-строк), чтобы проверить
// саму границу встраивания (C ABI + runtime-загрузка из Go без cgo).
//
// Этот крейт работает полностью самостоятельно. Hardening-слой (платный,
// см. ../../hardening-stub) — опциональная надстройка сверху, core не
// деградирует и не требует её присутствия.

use std::ffi::CStr;
use std::os::raw::c_char;

/// Сравнивает две C-строки на точное совпадение.
/// Возвращает 1 (true) при совпадении, 0 (false) иначе — включая
/// null-указатели и невалидный UTF-8, чтобы не паниковать через FFI-границу.
///
/// # Safety
/// `a` и `b` должны указывать либо на null, либо на валидную
/// null-terminated C-строку, живую на момент вызова.
#[no_mangle]
pub extern "C" fn verify_strings(a: *const c_char, b: *const c_char) -> i32 {
    if a.is_null() || b.is_null() {
        return 0;
    }

    let result = std::panic::catch_unwind(|| {
        let sa = unsafe { CStr::from_ptr(a) };
        let sb = unsafe { CStr::from_ptr(b) };
        match (sa.to_str(), sb.to_str()) {
            (Ok(x), Ok(y)) => x == y,
            _ => false,
        }
    });

    match result {
        Ok(true) => 1,
        _ => 0,
    }
}

/// Версия ABI-контракта core-библиотеки. Hardening-слой при загрузке
/// проверяет совместимость через эту константу, а не наоборот — core
/// ничего не знает про hardening и не ссылается на него напрямую.
#[no_mangle]
pub extern "C" fn keyforge_core_abi_version() -> i32 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn matches_equal_strings() {
        let a = CString::new("secret-key-123").unwrap();
        let b = CString::new("secret-key-123").unwrap();
        assert_eq!(verify_strings(a.as_ptr(), b.as_ptr()), 1);
    }

    #[test]
    fn rejects_different_strings() {
        let a = CString::new("secret-key-123").unwrap();
        let b = CString::new("wrong-key").unwrap();
        assert_eq!(verify_strings(a.as_ptr(), b.as_ptr()), 0);
    }

    #[test]
    fn rejects_null() {
        let a = CString::new("x").unwrap();
        assert_eq!(verify_strings(std::ptr::null(), a.as_ptr()), 0);
    }

    #[test]
    fn reports_abi_version() {
        assert_eq!(keyforge_core_abi_version(), 1);
    }
}
