const DATE_FORMAT: Intl.DateTimeFormatOptions = {
  day: '2-digit',
  month: 'short',
  year: 'numeric',
};

const DATE_TIME_FORMAT: Intl.DateTimeFormatOptions = {
  ...DATE_FORMAT,
  hour: '2-digit',
  minute: '2-digit',
};

export function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString('en-IN', DATE_FORMAT);
}

export function formatDateTime(iso: string): string {
  return new Date(iso).toLocaleString('en-IN', DATE_TIME_FORMAT);
}

export function truncate(text: string, maxLength: number): string {
  return text.length > maxLength ? `${text.slice(0, maxLength).trimEnd()}...` : text;
}
