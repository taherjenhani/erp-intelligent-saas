type MetricLabels = Record<
  string,
  string | number | boolean | null | undefined
>;

type MetricSample = {
  help: string;
  type: "counter" | "gauge";
  value: number;
  labels: Record<string, string>;
};

const samples = new Map<string, MetricSample>();

function normalizeLabels(labels: MetricLabels = {}) {
  return Object.fromEntries(
    Object.entries(labels)
      .filter(([, value]) => value !== undefined && value !== null)
      .map(([key, value]) => [key, String(value)])
      .sort(([left], [right]) => left.localeCompare(right))
  );
}

function sampleKey(name: string, labels: Record<string, string>) {
  return `${name}:${JSON.stringify(labels)}`;
}

function getSample(
  name: string,
  help: string,
  type: "counter" | "gauge",
  labels: MetricLabels
) {
  const normalizedLabels = normalizeLabels(labels);
  const key = sampleKey(name, normalizedLabels);
  const sample = samples.get(key);

  if (sample) {
    return sample;
  }

  const createdSample: MetricSample = {
    help,
    type,
    value: 0,
    labels: normalizedLabels,
  };

  samples.set(key, createdSample);
  return createdSample;
}

export function incrementCounter(
  name: string,
  help: string,
  labels: MetricLabels = {},
  value = 1
) {
  const sample = getSample(name, help, "counter", labels);
  sample.value += value;
}

export function setGauge(
  name: string,
  help: string,
  labels: MetricLabels = {},
  value: number
) {
  const sample = getSample(name, help, "gauge", labels);
  sample.value = value;
}

function escapeLabelValue(value: string) {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

function renderLabels(labels: Record<string, string>) {
  const entries = Object.entries(labels);

  if (entries.length === 0) {
    return "";
  }

  return `{${entries
    .map(([key, value]) => `${key}="${escapeLabelValue(value)}"`)
    .join(",")}}`;
}

export function renderMetrics() {
  const lines: string[] = [];
  const emittedDefinitions = new Set<string>();

  for (const [key, sample] of samples) {
    const name = key.slice(0, key.indexOf(":"));

    if (!emittedDefinitions.has(name)) {
      lines.push(`# HELP ${name} ${sample.help}`);
      lines.push(`# TYPE ${name} ${sample.type}`);
      emittedDefinitions.add(name);
    }

    lines.push(`${name}${renderLabels(sample.labels)} ${sample.value}`);
  }

  return `${lines.join("\n")}\n`;
}

export function resetMetricsForTests() {
  samples.clear();
}
