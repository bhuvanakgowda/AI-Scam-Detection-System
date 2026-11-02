export function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email.trim());
}

export interface PasswordCheck {
  key: 'length' | 'upper' | 'lower' | 'number' | 'symbol';
  label: string;
  passed: boolean;
}

export function getPasswordChecks(password: string): PasswordCheck[] {
  return [
    { key: 'length', label: 'At least 8 characters', passed: password.length >= 8 },
    { key: 'upper', label: 'One uppercase letter', passed: /[A-Z]/.test(password) },
    { key: 'lower', label: 'One lowercase letter', passed: /[a-z]/.test(password) },
    { key: 'number', label: 'One number', passed: /\d/.test(password) },
    { key: 'symbol', label: 'One symbol (for example ! or @)', passed: /[^A-Za-z0-9]/.test(password) },
  ];
}

export function isStrongPassword(password: string): boolean {
  return getPasswordChecks(password).every((check) => check.passed);
}
