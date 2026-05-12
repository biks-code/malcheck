import { ScanReport } from '../types';

export function renderJsonReport(report: ScanReport): void {
  console.log(JSON.stringify(report, null, 2));
}
