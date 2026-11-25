/**
 * Pure Intl.DateTimeFormat timestamp and duration formatting helpers.
 * Never outputs em-dashes or spaced en-dashes.
 */

const clockFormatter = new Intl.DateTimeFormat(undefined, {
	hour: 'numeric',
	minute: '2-digit'
});

const weekdayFormatter = new Intl.DateTimeFormat(undefined, {
	weekday: 'short'
});

const sameYearDateFormatter = new Intl.DateTimeFormat(undefined, {
	month: 'short',
	day: 'numeric'
});

const fullDateFormatter = new Intl.DateTimeFormat(undefined, {
	month: 'short',
	day: 'numeric',
	year: 'numeric'
});

function toValidDate(input: string | number | Date | null | undefined): Date | null {
	if (input == null || input === '') return null;
	const date = input instanceof Date ? input : new Date(input);
	return Number.isNaN(date.getTime()) ? null : date;
}

export function isSameCalendarDay(
	a: string | number | Date | null | undefined,
	b: string | number | Date | null | undefined
): boolean {
	const da = toValidDate(a);
	const db = toValidDate(b);
	if (!da || !db) return false;
	return (
		da.getFullYear() === db.getFullYear() &&
		da.getMonth() === db.getMonth() &&
		da.getDate() === db.getDate()
	);
}

function isYesterday(target: Date, now: Date): boolean {
	const yesterday = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 1);
	return isSameCalendarDay(target, yesterday);
}

export function formatClockTime(iso: string | number | Date | null | undefined): string {
	const date = toValidDate(iso);
	if (!date) return '';
	return clockFormatter.format(date);
}

export function formatSidebarTime(
	iso: string | number | Date | null | undefined,
	now: Date = new Date()
): string {
	const date = toValidDate(iso);
	if (!date) return '';

	if (isSameCalendarDay(date, now)) {
		return clockFormatter.format(date);
	}
	if (isYesterday(date, now)) {
		return 'Yesterday';
	}

	const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
	const startOfTarget = new Date(date.getFullYear(), date.getMonth(), date.getDate()).getTime();
	const daysAgo = Math.round((startOfToday - startOfTarget) / 86_400_000);

	if (daysAgo > 1 && daysAgo < 7) {
		return weekdayFormatter.format(date);
	}
	if (date.getFullYear() === now.getFullYear()) {
		return sameYearDateFormatter.format(date);
	}
	return fullDateFormatter.format(date);
}

export function formatDayDivider(
	iso: string | number | Date | null | undefined,
	now: Date = new Date()
): string {
	const date = toValidDate(iso);
	if (!date) return '';

	if (isSameCalendarDay(date, now)) {
		return 'Today';
	}
	if (isYesterday(date, now)) {
		return 'Yesterday';
	}
	if (date.getFullYear() === now.getFullYear()) {
		return sameYearDateFormatter.format(date);
	}
	return fullDateFormatter.format(date);
}

export function formatDuration(ms: number): string {
	if (!Number.isFinite(ms) || ms <= 0) {
		return '0:00';
	}
	const totalSeconds = Math.max(0, Math.round(ms / 1000));
	const hours = Math.floor(totalSeconds / 3600);
	const minutes = Math.floor((totalSeconds % 3600) / 60);
	const seconds = totalSeconds % 60;
	const secStr = String(seconds).padStart(2, '0');
	if (hours > 0) {
		return `${hours}:${String(minutes).padStart(2, '0')}:${secStr}`;
	}
	return `${minutes}:${secStr}`;
}
