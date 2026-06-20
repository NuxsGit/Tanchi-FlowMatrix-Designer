import {
  ChangeEvent,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { invoke } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";
import Logo from "./assets/Logo_GTanchi.svg";
import "./App.css";

type FlowAction = "ALLOW" | "DENY";
type FlowStatus = "PENDING" | "APPROVED" | "REJECTED";

type Section = {
  id: string;
  name: string;
  color: string;
};

type AddressObject = {
  id: string;
  name: string;
  value: string;
  comment: string;
};

type ServiceObject = {
  id: string;
  name: string;
  protocol: string;
  port: string;
  comment: string;
};

type MatrixObjects = {
  addresses: AddressObject[];
  services: ServiceObject[];
};

type Flow = {
  id: string;
  ruleName: string;
  source: string;
  nomSource: string;
  destination: string;
  nomDestination: string;
  application: string;
  protocol: string;
  action: FlowAction;
  status: FlowStatus;
  fromZone: string;
  toZone: string;
  natSrc: string;
  natDst: string;
  comment: string;
  sectionId: string | null;
};

type Matrix = {
  id: string;
  name: string;
  flows: Flow[];
  sections: Section[];
  objects: MatrixObjects;
  createdAt: string;
  updatedAt: string;
};

type FlowForm = {
  ruleName: string;
  source: string;
  nomSource: string;
  destination: string;
  nomDestination: string;
  application: string;
  protocol: string;
  action: FlowAction;
  fromZone: string;
  toZone: string;
  natSrc: string;
  natDst: string;
  comment: string;
  sectionId: string;
};

type PersistedState = {
  matrices: Matrix[];
  activeMatrixId: string;
};

const STORAGE_KEY = "tanchi-flowmatrix-react-v1";
const THEME_KEY = "tanchi-theme";

const SECTION_COLORS = [
  "#08A87C",
  "#3B82F6",
  "#F59E0B",
  "#8B5CF6",
  "#EC4899",
  "#10B981",
  "#F97316",
  "#6366F1",
  "#EF4444",
  "#06B6D4",
];

const APP_PROTOCOLS: Record<string, string> = {
  HTTP: "80/TCP",
  HTTPS: "443/TCP",
  SSH: "22/TCP",
  TELNET: "23/TCP",
  FTP: "21/TCP",
  SMTP: "25/TCP",
  DNS: "53/UDP",
  LDAP: "389/TCP",
  LDAPS: "636/TCP",
  KERBEROS: "88/TCP",
  RDP: "3389/TCP",
  SMB: "445/TCP",
  SNMP: "161/UDP",
  SYSLOG: "514/UDP",
  NTP: "123/UDP",
  MYSQL: "3306/TCP",
  MSSQL: "1433/TCP",
  POSTGRESQL: "5432/TCP",
  ORACLE: "1521/TCP",
  WINRM: "5985/TCP",
  "WINRM-HTTPS": "5986/TCP",
  OPENVPN: "1194/UDP",
  WIREGUARD: "51820/UDP",
  BGP: "179/TCP",
};

const EMPTY_FORM: FlowForm = {
  ruleName: "",
  source: "",
  nomSource: "",
  destination: "",
  nomDestination: "",
  application: "",
  protocol: "",
  action: "ALLOW",
  fromZone: "TRUST",
  toZone: "SERVERS",
  natSrc: "",
  natDst: "",
  comment: "",
  sectionId: "",
};

const EMPTY_OBJECTS: MatrixObjects = {
  addresses: [],
  services: [],
};

function genId() {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

function normalize(value: unknown) {
  return String(value ?? "").trim();
}

function createSection(name: string, index: number): Section {
  return {
    id: genId(),
    name: normalize(name),
    color: SECTION_COLORS[index % SECTION_COLORS.length],
  };
}

function createMatrix(name = "Matrice 1"): Matrix {
  const now = new Date().toISOString();
  return {
    id: genId(),
    name,
    flows: [],
    sections: [],
    objects: { ...EMPTY_OBJECTS },
    createdAt: now,
    updatedAt: now,
  };
}

function normalizeMatrix(matrix: Matrix): Matrix {
  return {
    ...matrix,
    objects: {
      addresses: Array.isArray(matrix.objects?.addresses)
        ? matrix.objects.addresses.map((address) => ({
            id: address.id ?? genId(),
            name: normalize(address.name).toUpperCase(),
            value: normalize(address.value),
            comment: normalize(address.comment),
          }))
        : [],
      services: Array.isArray(matrix.objects?.services)
        ? matrix.objects.services.map((service) => ({
            id: service.id ?? genId(),
            name: normalize(service.name).toUpperCase(),
            protocol: normalizeProtocol(service.protocol),
            port: normalize(service.port),
            comment: normalize(service.comment),
          }))
        : [],
    },
  };
}

function loadInitialState(): PersistedState {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      const matrix = createMatrix();
      return { matrices: [matrix], activeMatrixId: matrix.id };
    }

    const parsed = JSON.parse(raw) as Partial<PersistedState>;
    const matrices =
      Array.isArray(parsed.matrices) && parsed.matrices.length
        ? parsed.matrices.map((matrix) => normalizeMatrix(matrix as Matrix))
        : [createMatrix()];

    const activeMatrixId = matrices.some(
      (matrix) => matrix.id === parsed.activeMatrixId,
    )
      ? (parsed.activeMatrixId as string)
      : matrices[0].id;

    return { matrices, activeMatrixId };
  } catch {
    const matrix = createMatrix();
    return { matrices: [matrix], activeMatrixId: matrix.id };
  }
}

function getInitialTheme() {
  const stored = localStorage.getItem(THEME_KEY);
  if (stored === "dark" || stored === "light") return stored;
  return window.matchMedia("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light";
}

function isValidProtocolToken(value: string) {
  const token = normalize(value);
  if (!token) return false;
  if (/^any$/i.test(token)) return true;

  const match = token.match(/^(\d{1,5})(?:-(\d{1,5}))?\/(tcp|udp)$/i);
  if (!match) return false;

  const start = Number(match[1]);
  const end = Number(match[2] ?? match[1]);
  return (
    start >= 1 && start <= 65535 && end >= 1 && end <= 65535 && start <= end
  );
}

function isValidProtocol(value: string) {
  const normalized = normalize(value);
  if (!normalized) return false;
  return normalized
    .split(",")
    .map((token) => token.trim())
    .filter(Boolean)
    .every(isValidProtocolToken);
}

function normalizeProtocol(value: string) {
  return normalize(value)
    .split(",")
    .map((token) => token.trim())
    .filter(Boolean)
    .map((token) => {
      if (/^any$/i.test(token)) return "any";
      const match = token.match(/^(\d{1,5})(?:-(\d{1,5}))?\/(tcp|udp)$/i);
      if (!match) return token.toUpperCase();
      const start = Number(match[1]);
      const end = match[2] ? Number(match[2]) : null;
      const proto = match[3].toUpperCase();
      return `${start}${end ? `-${end}` : ""}/${proto}`;
    })
    .join(", ");
}

function getApplicationProtocol(application: string) {
  const key = Object.keys(APP_PROTOCOLS).find(
    (item) => item.toLowerCase() === normalize(application).toLowerCase(),
  );
  return key ? APP_PROTOCOLS[key] : "";
}

function buildConflictKey(
  flow: Pick<Flow, "source" | "destination" | "protocol">,
) {
  const source = normalize(flow.source).toLowerCase();
  const destination = normalize(flow.destination).toLowerCase();
  const protocol = normalize(flow.protocol).toLowerCase();
  return source && destination && protocol
    ? `${source}|${destination}|${protocol}`
    : "";
}

function statusLabel(status: FlowStatus) {
  if (status === "APPROVED") return "APPROUVÉ";
  if (status === "REJECTED") return "REFUSÉ";
  return "PENDING";
}

function splitValues(value: string) {
  return normalize(value)
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function buildJuniperApplication(flow: Flow) {
  const apps = splitValues(flow.application);
  const protocols = splitValues(flow.protocol);

  if (apps.length > 1) return `[ ${apps.join(" ")} ]`;
  if (apps.length === 1) return apps[0];
  if (protocols.length > 1) {
    return `[ ${protocols.map((item) => (item === "any" ? "any" : `junos-${item.replace("/", "-").toLowerCase()}`)).join(" ")} ]`;
  }
  if (protocols[0])
    return protocols[0] === "any"
      ? "any"
      : `junos-${protocols[0].replace("/", "-").toLowerCase()}`;
  return "any";
}

function buildPolicyName(flow: Flow, index: number) {
  const base = `${index + 1}-${flow.source}-${flow.destination}-${flow.application || flow.protocol}`;
  return base
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function buildJuniperConfig(flows: Flow[]) {
  if (!flows.length) return "Aucun flux pour le moment.";

  const lines: string[] = ["# TANCHI - Flow Matrix Designer", ""];

  flows.forEach((flow, index) => {
    const policyName = buildPolicyName(flow, index);
    const source = splitValues(flow.source);
    const destination = splitValues(flow.destination);
    const sourceValue =
      source.length > 1 ? `[ ${source.join(" ")} ]` : source[0] || "any";
    const destinationValue =
      destination.length > 1
        ? `[ ${destination.join(" ")} ]`
        : destination[0] || "any";

    lines.push(
      `# ${index + 1} - ${flow.ruleName || `${flow.source} -> ${flow.destination}`}`,
    );
    lines.push(
      `set security policies from-zone ${flow.fromZone} to-zone ${flow.toZone} policy ${policyName} match source-address ${sourceValue}`,
    );
    lines.push(
      `set security policies from-zone ${flow.fromZone} to-zone ${flow.toZone} policy ${policyName} match destination-address ${destinationValue}`,
    );
    lines.push(
      `set security policies from-zone ${flow.fromZone} to-zone ${flow.toZone} policy ${policyName} match application ${buildJuniperApplication(flow)}`,
    );
    lines.push(
      `set security policies from-zone ${flow.fromZone} to-zone ${flow.toZone} policy ${policyName} then ${flow.action.toLowerCase()}`,
    );

    if (flow.natSrc) {
      lines.push(`# Source NAT: ${flow.natSrc}`);
    }
    if (flow.natDst) {
      lines.push(`# Destination NAT: ${flow.natDst}`);
    }
    if (flow.comment) {
      lines.push(`# Commentaire: ${flow.comment}`);
    }

    lines.push("");
  });

  return lines.join("\n");
}

function csvEscape(value: string) {
  return /[",\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}

function downloadText(
  filename: string,
  content: string,
  mime = "text/plain;charset=utf-8",
) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function normalizeImportedFlow(
  raw: Record<string, unknown>,
  resolveSectionId: (
    rawSectionId: unknown,
    rawSectionName: unknown,
  ) => string | null,
): Flow | null {
  const source = normalize(raw.source ?? raw.Source ?? raw.src ?? raw.Src);
  const destination = normalize(
    raw.destination ?? raw.Destination ?? raw.dst ?? raw.Dst,
  );
  const protocol = normalizeProtocol(
    normalize(
      raw.protocol ??
        raw.Protocol ??
        raw.proto ??
        raw["Port/Protocol"] ??
        raw["port/protocol"],
    ),
  );

  if (!source || !destination || !protocol || !isValidProtocol(protocol))
    return null;

  const action =
    normalize(raw.action ?? raw.Action).toUpperCase() === "DENY"
      ? "DENY"
      : "ALLOW";
  const statusRaw = normalize(raw.status ?? raw.Status).toUpperCase();
  const status: FlowStatus =
    statusRaw === "APPROVED" || statusRaw === "REJECTED"
      ? statusRaw
      : "PENDING";

  return {
    id: genId(),
    ruleName: normalize(raw.ruleName ?? raw["Rule Name"] ?? raw.rule_name),
    source,
    nomSource: normalize(raw.nomSource ?? raw.nom_source ?? raw["Nom source"]),
    destination,
    nomDestination: normalize(
      raw.nomDestination ?? raw.nom_destination ?? raw["Nom destination"],
    ),
    application: normalize(
      raw.application ?? raw.Application ?? raw.app ?? raw.App,
    ),
    protocol,
    action,
    status,
    fromZone:
      normalize(raw.fromZone ?? raw.FromZone ?? raw["Zone source"]) || "TRUST",
    toZone:
      normalize(raw.toZone ?? raw.ToZone ?? raw["Zone destination"]) ||
      "SERVERS",
    natSrc: normalize(raw.natSrc ?? raw.nat_src ?? raw["Source NAT"]),
    natDst: normalize(raw.natDst ?? raw.nat_dst ?? raw["Destination NAT"]),
    comment: normalize(raw.comment ?? raw.Comment ?? raw.Commentaire),
    sectionId: resolveSectionId(raw.sectionId, raw.sectionName ?? raw.Section),
  };
}

function BrandMark() {
  return <img className="brand-mark" src={Logo} alt="Tanchi" />;
}

function App() {
  const initial = loadInitialState();
  const [matrices, setMatrices] = useState<Matrix[]>(initial.matrices);
  const [activeMatrixId, setActiveMatrixId] = useState(initial.activeMatrixId);
  const [theme, setTheme] = useState<"light" | "dark">(getInitialTheme);
  const [form, setForm] = useState<FlowForm>(EMPTY_FORM);
  const [editingFlowId, setEditingFlowId] = useState<string | null>(null);
  const [tableQuery, setTableQuery] = useState("");
  const [diagramQuery, setDiagramQuery] = useState("");
  const [diagramStatus, setDiagramStatus] = useState<"ACTIVE" | FlowStatus>(
    "ACTIVE",
  );
  const [diagramAction, setDiagramAction] = useState<"ALL" | FlowAction>("ALL");
  const [selectedRelationKey, setSelectedRelationKey] = useState("");
  const [isObjectsModalOpen, setIsObjectsModalOpen] = useState(false);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [toolboxTab, setToolboxTab] = useState<
    "composer" | "sections" | "bulk" | "export" | "config"
  >("composer");
  const [objectTab, setObjectTab] = useState<"addresses" | "services">(
    "addresses",
  );
  const [addressDraft, setAddressDraft] = useState({
    name: "",
    value: "",
    comment: "",
  });
  const [serviceDraft, setServiceDraft] = useState({
    name: "",
    protocol: "",
    port: "",
    comment: "",
  });
  const [exportFeedback, setExportFeedback] = useState("");
  const [lastSavedAt, setLastSavedAt] = useState<string | null>(null);
  const [selectedFlowIds, setSelectedFlowIds] = useState<Set<string>>(
    new Set(),
  );
  const [bulkField, setBulkField] = useState("action");
  const [bulkValue, setBulkValue] = useState("ALLOW");
  const [flowsHistory, setFlowsHistory] = useState<Flow[][]>([]);
  const importInputRef = useRef<HTMLInputElement | null>(null);

  const activeMatrix = useMemo(
    () =>
      matrices.find((matrix) => matrix.id === activeMatrixId) ?? matrices[0],
    [matrices, activeMatrixId],
  );

  const flows = activeMatrix?.flows ?? [];
  const sections = activeMatrix?.sections ?? [];
  const objects = activeMatrix?.objects ?? EMPTY_OBJECTS;

  const addressOptions = useMemo(() => {
    const names = new Set<string>();
    objects.addresses.forEach((address) => names.add(address.name));
    return [...names].sort((left, right) =>
      left.localeCompare(right, "fr", { sensitivity: "base" }),
    );
  }, [objects.addresses]);

  const serviceOptions = useMemo(() => {
    const names = new Set<string>(Object.keys(APP_PROTOCOLS));
    objects.services.forEach((service) => names.add(service.name));
    return [...names].sort((left, right) =>
      left.localeCompare(right, "fr", { sensitivity: "base" }),
    );
  }, [objects.services]);

  useEffect(() => {
    document.body.classList.toggle("dark-mode", theme === "dark");
    localStorage.setItem(THEME_KEY, theme);
  }, [theme]);

  useEffect(() => {
    if (!activeMatrix && matrices.length) {
      setActiveMatrixId(matrices[0].id);
    }
  }, [activeMatrix, matrices]);

  useEffect(() => {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({ matrices, activeMatrixId }),
    );
    setLastSavedAt(new Date().toISOString());
  }, [matrices, activeMatrixId]);

  const updateActiveMatrix = (updater: (matrix: Matrix) => Matrix) => {
    setMatrices((current) =>
      current.map((matrix) =>
        matrix.id === activeMatrixId
          ? { ...updater(matrix), updatedAt: new Date().toISOString() }
          : matrix,
      ),
    );
  };

  const conflictKeys = useMemo(() => {
    const counts = new Map<string, number>();
    flows.forEach((flow) => {
      const key = buildConflictKey(flow);
      if (!key) return;
      counts.set(key, (counts.get(key) ?? 0) + 1);
    });
    return new Set(
      [...counts.entries()]
        .filter(([, count]) => count > 1)
        .map(([key]) => key),
    );
  }, [flows]);

  const stats = useMemo(() => {
    return {
      total: flows.length,
      allow: flows.filter((flow) => flow.action === "ALLOW").length,
      deny: flows.filter((flow) => flow.action === "DENY").length,
      conflicts: flows.filter((flow) =>
        conflictKeys.has(buildConflictKey(flow)),
      ).length,
    };
  }, [conflictKeys, flows]);

  const displayedFlows = useMemo(() => {
    const query = normalize(tableQuery).toLowerCase();
    if (!query) return flows;

    return flows.filter((flow) =>
      [
        flow.ruleName,
        flow.source,
        flow.nomSource,
        flow.destination,
        flow.nomDestination,
        flow.application,
        flow.protocol,
        flow.action,
        flow.status,
        flow.fromZone,
        flow.toZone,
        flow.comment,
      ]
        .join(" ")
        .toLowerCase()
        .includes(query),
    );
  }, [flows, tableQuery]);

  const relationGroups = useMemo(() => {
    const query = normalize(diagramQuery).toLowerCase();
    const relationMap = new Map<
      string,
      { source: string; destination: string; flows: Flow[] }
    >();

    flows.forEach((flow) => {
      if (!flow.source || !flow.destination) return;
      if (flow.status === "REJECTED") return;
      if (diagramStatus !== "ACTIVE" && flow.status !== diagramStatus) return;
      if (diagramAction !== "ALL" && flow.action !== diagramAction) return;

      const source = normalize(flow.source);
      const destination = normalize(flow.destination);
      const matchesQuery =
        !query ||
        source.toLowerCase().includes(query) ||
        destination.toLowerCase().includes(query);
      if (!matchesQuery) return;

      const key = `${source.toLowerCase()}|${destination.toLowerCase()}`;
      const group = relationMap.get(key) ?? { source, destination, flows: [] };
      group.flows.push(flow);
      relationMap.set(key, group);
    });

    return [...relationMap.entries()]
      .map(([key, value]) => ({ key, ...value }))
      .sort((a, b) =>
        `${a.source} ${a.destination}`.localeCompare(
          `${b.source} ${b.destination}`,
          "fr",
          { sensitivity: "base" },
        ),
      );
  }, [flows, diagramAction, diagramQuery, diagramStatus]);

  useEffect(() => {
    if (!relationGroups.length) {
      setSelectedRelationKey("");
      return;
    }
    if (
      !relationGroups.some((relation) => relation.key === selectedRelationKey)
    ) {
      setSelectedRelationKey(relationGroups[0].key);
    }
  }, [relationGroups, selectedRelationKey]);

  const selectedRelation = useMemo(
    () =>
      relationGroups.find((relation) => relation.key === selectedRelationKey) ??
      null,
    [relationGroups, selectedRelationKey],
  );

  const diagramGraph = useMemo(() => {
    const sourceNames = [
      ...new Set(relationGroups.map((relation) => relation.source)),
    ];
    const destinationNames = [
      ...new Set(relationGroups.map((relation) => relation.destination)),
    ];

    const height = Math.max(
      320,
      Math.max(sourceNames.length, destinationNames.length) * 96,
    );
    const nodeMap = new Map<
      string,
      { x: number; y: number; side: "source" | "destination" }
    >();

    sourceNames.forEach((name, index) => {
      nodeMap.set(`source:${name}`, {
        x: 180,
        y: 64 + index * 96,
        side: "source",
      });
    });

    destinationNames.forEach((name, index) => {
      nodeMap.set(`destination:${name}`, {
        x: 780,
        y: 64 + index * 96,
        side: "destination",
      });
    });

    return {
      width: 960,
      height,
      sourceNames,
      destinationNames,
      nodeMap,
    };
  }, [relationGroups]);

  const juniperConfig = useMemo(() => buildJuniperConfig(flows), [flows]);

  const saveStatusLabel = useMemo(() => {
    if (!lastSavedAt) return "Autosauvegarde active";
    return `Sauvegardé à ${new Date(lastSavedAt).toLocaleTimeString("fr-FR", {
      hour: "2-digit",
      minute: "2-digit",
    })}`;
  }, [lastSavedAt]);

  // ── Réinitialise l'historique et la sélection au changement de matrice ──
  useEffect(() => {
    setFlowsHistory([]);
    setSelectedFlowIds(new Set());
  }, [activeMatrixId]);

  const pushHistory = useCallback(() => {
    const snapshot = [...(activeMatrix?.flows ?? [])];
    setFlowsHistory((prev) => {
      const next = [...prev, snapshot];
      return next.length > 30 ? next.slice(-30) : next;
    });
  }, [activeMatrix?.flows]);

  const undo = useCallback(() => {
    setFlowsHistory((prev) => {
      if (!prev.length) return prev;
      const previousFlows = prev[prev.length - 1];
      updateActiveMatrix((matrix) => ({ ...matrix, flows: previousFlows }));
      return prev.slice(0, -1);
    });
  }, [updateActiveMatrix]);

  // ── Raccourcis clavier globaux ────────────────────────────────────────
  const undoRef = useRef(undo);
  useEffect(() => {
    undoRef.current = undo;
  });

  const saveRef = useRef<() => void>(() => {});

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const inField =
        e.target instanceof HTMLInputElement ||
        e.target instanceof HTMLTextAreaElement ||
        e.target instanceof HTMLSelectElement;

      if ((e.ctrlKey || e.metaKey) && e.key === "z" && !e.shiftKey) {
        if (!inField) {
          e.preventDefault();
          undoRef.current();
        }
      }
      if ((e.ctrlKey || e.metaKey) && e.key === "s") {
        e.preventDefault();
        saveRef.current();
      }
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, []);

  const protocolIsValid = !form.protocol || isValidProtocol(form.protocol);
  const canSubmit = Boolean(
    normalize(form.source) &&
    normalize(form.destination) &&
    normalize(form.protocol) &&
    protocolIsValid,
  );

  const handleFormChange = (
    event: ChangeEvent<
      HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement
    >,
  ) => {
    const { name, value } = event.target;

    setForm((current) => {
      const next = { ...current, [name]: value };
      if (name === "application" && !normalize(current.protocol)) {
        const builtInProtocol = getApplicationProtocol(value);
        const serviceObject = objects.services.find(
          (service) =>
            service.name.toLowerCase() === normalize(value).toLowerCase(),
        );
        const objectProtocol = serviceObject?.protocol
          ? normalizeProtocol(serviceObject.protocol)
          : serviceObject?.port && serviceObject.protocol
            ? normalizeProtocol(
                `${serviceObject.port}/${serviceObject.protocol}`,
              )
            : "";
        const protocol = builtInProtocol || objectProtocol;
        if (protocol) next.protocol = protocol;
      }
      return next;
    });
  };

  const resetForm = () => {
    setForm(EMPTY_FORM);
    setEditingFlowId(null);
  };

  const submitFlow = () => {
    if (!canSubmit) return;
    pushHistory();

    const normalizedProtocol = normalizeProtocol(form.protocol);

    const baseFlow: Omit<Flow, "id" | "status"> = {
      ruleName: normalize(form.ruleName),
      source: normalize(form.source),
      nomSource: normalize(form.nomSource),
      destination: normalize(form.destination),
      nomDestination: normalize(form.nomDestination),
      application: normalize(form.application),
      protocol: normalizedProtocol,
      action: form.action,
      fromZone: normalize(form.fromZone) || "TRUST",
      toZone: normalize(form.toZone) || "SERVERS",
      natSrc: normalize(form.natSrc),
      natDst: normalize(form.natDst),
      comment: normalize(form.comment),
      sectionId: form.sectionId || null,
    };

    updateActiveMatrix((matrix) => {
      const flowsNext = [...matrix.flows];
      const index = flowsNext.findIndex((flow) => flow.id === editingFlowId);

      if (index >= 0) {
        flowsNext[index] = {
          ...flowsNext[index],
          ...baseFlow,
        };
      } else {
        flowsNext.push({
          id: genId(),
          status: "PENDING",
          ...baseFlow,
        });
      }

      return { ...matrix, flows: flowsNext };
    });

    resetForm();
  };

  const editFlow = (flow: Flow) => {
    setEditingFlowId(flow.id);
    setForm({
      ruleName: flow.ruleName,
      source: flow.source,
      nomSource: flow.nomSource,
      destination: flow.destination,
      nomDestination: flow.nomDestination,
      application: flow.application,
      protocol: flow.protocol,
      action: flow.action,
      fromZone: flow.fromZone,
      toZone: flow.toZone,
      natSrc: flow.natSrc,
      natDst: flow.natDst,
      comment: flow.comment,
      sectionId: flow.sectionId ?? "",
    });
  };

  const duplicateFlow = (flowId: string) => {
    pushHistory();
    updateActiveMatrix((matrix) => {
      const original = matrix.flows.find((flow) => flow.id === flowId);
      if (!original) return matrix;
      return {
        ...matrix,
        flows: [
          ...matrix.flows,
          { ...original, id: genId(), status: "PENDING" },
        ],
      };
    });
  };

  const deleteFlow = (flowId: string) => {
    pushHistory();
    updateActiveMatrix((matrix) => ({
      ...matrix,
      flows: matrix.flows.filter((flow) => flow.id !== flowId),
    }));

    if (editingFlowId === flowId) resetForm();
  };

  const updateFlowStatus = (flowId: string, status: FlowStatus) => {
    pushHistory();
    updateActiveMatrix((matrix) => ({
      ...matrix,
      flows: matrix.flows.map((flow) =>
        flow.id === flowId ? { ...flow, status } : flow,
      ),
    }));
  };

  const moveFlow = (flowId: string, direction: "up" | "down") => {
    pushHistory();
    updateActiveMatrix((matrix) => {
      const index = matrix.flows.findIndex((flow) => flow.id === flowId);
      if (index < 0) return matrix;

      const targetIndex = direction === "up" ? index - 1 : index + 1;
      if (targetIndex < 0 || targetIndex >= matrix.flows.length) return matrix;

      const flowsNext = [...matrix.flows];
      [flowsNext[index], flowsNext[targetIndex]] = [
        flowsNext[targetIndex],
        flowsNext[index],
      ];
      return { ...matrix, flows: flowsNext };
    });
  };

  const applyBulkEdit = () => {
    if (!selectedFlowIds.size) return;
    pushHistory();
    updateActiveMatrix((matrix) => ({
      ...matrix,
      flows: matrix.flows.map((flow) => {
        if (!selectedFlowIds.has(flow.id)) return flow;
        if (bulkField === "action")
          return { ...flow, action: bulkValue as FlowAction };
        if (bulkField === "status")
          return { ...flow, status: bulkValue as FlowStatus };
        return { ...flow, [bulkField]: bulkValue };
      }),
    }));
    setSelectedFlowIds(new Set());
  };

  const bulkSwapSrcDst = () => {
    if (!selectedFlowIds.size) return;
    pushHistory();
    updateActiveMatrix((matrix) => ({
      ...matrix,
      flows: matrix.flows.map((flow) => {
        if (!selectedFlowIds.has(flow.id)) return flow;
        return {
          ...flow,
          source: flow.destination,
          destination: flow.source,
          nomSource: flow.nomDestination,
          nomDestination: flow.nomSource,
        };
      }),
    }));
  };

  const swapSourceDestination = () => {
    setForm((current) => ({
      ...current,
      source: current.destination,
      destination: current.source,
      nomSource: current.nomDestination,
      nomDestination: current.nomSource,
    }));
  };

  const addSection = () => {
    const name = window.prompt("Nom de la section :");
    if (!name || !normalize(name)) return;

    updateActiveMatrix((matrix) => {
      const exists = matrix.sections.some(
        (section) =>
          section.name.toLowerCase() === normalize(name).toLowerCase(),
      );
      if (exists) return matrix;

      return {
        ...matrix,
        sections: [
          ...matrix.sections,
          createSection(name, matrix.sections.length),
        ],
      };
    });
  };

  const deleteSection = (sectionId: string) => {
    updateActiveMatrix((matrix) => ({
      ...matrix,
      sections: matrix.sections.filter((section) => section.id !== sectionId),
      flows: matrix.flows.map((flow) =>
        flow.sectionId === sectionId ? { ...flow, sectionId: null } : flow,
      ),
    }));

    setForm((current) =>
      current.sectionId === sectionId ? { ...current, sectionId: "" } : current,
    );
  };

  const addAddressObject = () => {
    const name = normalize(addressDraft.name).toUpperCase();
    const value = normalize(addressDraft.value);
    if (!name || !value) return;

    updateActiveMatrix((matrix) => {
      const exists = matrix.objects.addresses.some(
        (address) => address.name.toLowerCase() === name.toLowerCase(),
      );
      if (exists) return matrix;

      return {
        ...matrix,
        objects: {
          ...matrix.objects,
          addresses: [
            ...matrix.objects.addresses,
            {
              id: genId(),
              name,
              value,
              comment: normalize(addressDraft.comment),
            },
          ],
        },
      };
    });

    setAddressDraft({ name: "", value: "", comment: "" });
  };

  const removeAddressObject = (addressId: string) => {
    updateActiveMatrix((matrix) => ({
      ...matrix,
      objects: {
        ...matrix.objects,
        addresses: matrix.objects.addresses.filter(
          (address) => address.id !== addressId,
        ),
      },
    }));
  };

  const addServiceObject = () => {
    const name = normalize(serviceDraft.name).toUpperCase();
    const protocol = normalizeProtocol(serviceDraft.protocol);
    const port = normalize(serviceDraft.port);
    if (!name || (!protocol && !port)) return;

    updateActiveMatrix((matrix) => {
      const exists = matrix.objects.services.some(
        (service) => service.name.toLowerCase() === name.toLowerCase(),
      );
      if (exists) return matrix;

      return {
        ...matrix,
        objects: {
          ...matrix.objects,
          services: [
            ...matrix.objects.services,
            {
              id: genId(),
              name,
              protocol,
              port,
              comment: normalize(serviceDraft.comment),
            },
          ],
        },
      };
    });

    setServiceDraft({ name: "", protocol: "", port: "", comment: "" });
  };

  const removeServiceObject = (serviceId: string) => {
    updateActiveMatrix((matrix) => ({
      ...matrix,
      objects: {
        ...matrix.objects,
        services: matrix.objects.services.filter(
          (service) => service.id !== serviceId,
        ),
      },
    }));
  };

  const saveWorkspaceNow = () => {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({ matrices, activeMatrixId }),
    );
    const savedAt = new Date().toISOString();
    setLastSavedAt(savedAt);
    setExportFeedback(
      "Espace de travail sauvegardé localement sur cet appareil.",
    );
  };

  // Branche saveWorkspaceNow dans la ref pour Ctrl+S
  useEffect(() => {
    saveRef.current = saveWorkspaceNow;
  });

  const resetWorkspace = () => {
    const confirmed = window.confirm(
      "Réinitialiser toutes les matrices locales ? Cette action supprime l’espace de travail enregistré sur cet appareil.",
    );
    if (!confirmed) return;

    const matrix = createMatrix();
    setMatrices([matrix]);
    setActiveMatrixId(matrix.id);
    setForm(EMPTY_FORM);
    setEditingFlowId(null);
    setExportFeedback("Espace de travail local réinitialisé.");
  };

  const addMatrix = () => {
    const matrix = createMatrix(`Matrice ${matrices.length + 1}`);
    setMatrices((current) => [...current, matrix]);
    setActiveMatrixId(matrix.id);
    resetForm();
  };

  const deleteMatrix = (matrixId: string) => {
    if (matrices.length === 1) return;
    const target = matrices.find((matrix) => matrix.id === matrixId);
    if (!target) return;
    const confirmed = window.confirm(`Supprimer « ${target.name} » ?`);
    if (!confirmed) return;

    const nextMatrices = matrices.filter((matrix) => matrix.id !== matrixId);
    setMatrices(nextMatrices);
    if (activeMatrixId === matrixId) {
      setActiveMatrixId(nextMatrices[0].id);
      resetForm();
    }
  };

  const writeExport = async (
    suggestedName: string,
    content: string,
    type: "json" | "csv",
  ) => {
    const mime =
      type === "json"
        ? "application/json;charset=utf-8"
        : "text/csv;charset=utf-8";

    try {
      const path = await save({
        defaultPath: suggestedName,
        filters: [
          {
            name: type.toUpperCase(),
            extensions: [type],
          },
        ],
      });

      if (!path) {
        setExportFeedback("Export annulé.");
        return;
      }

      await invoke("write_export_file", { path, contents: content });
      setExportFeedback(
        `Export ${type.toUpperCase()} enregistré dans : ${path}`,
      );
    } catch {
      downloadText(suggestedName, content, mime);
      setExportFeedback(
        `Export ${type.toUpperCase()} téléchargé via le navigateur.`,
      );
    }
  };

  const exportJson = async () => {
    if (!activeMatrix) return;
    const filename = `${activeMatrix.name.replace(/\s+/g, "-").toLowerCase()}-flow-matrix.json`;
    await writeExport(filename, JSON.stringify(activeMatrix, null, 2), "json");
  };

  const exportCsv = async () => {
    const headers = [
      "Rule Name",
      "Source",
      "Nom source",
      "Destination",
      "Nom destination",
      "Application",
      "Protocol",
      "Action",
      "Status",
      "Zone source",
      "Zone destination",
      "Source NAT",
      "Destination NAT",
      "Section",
      "Commentaire",
    ];

    const rows = flows.map((flow) => {
      const sectionName =
        sections.find((section) => section.id === flow.sectionId)?.name ?? "";
      return [
        flow.ruleName,
        flow.source,
        flow.nomSource,
        flow.destination,
        flow.nomDestination,
        flow.application,
        flow.protocol,
        flow.action,
        flow.status,
        flow.fromZone,
        flow.toZone,
        flow.natSrc,
        flow.natDst,
        sectionName,
        flow.comment,
      ]
        .map((item) => csvEscape(item))
        .join(",");
    });

    await writeExport(
      `${activeMatrix?.name.replace(/\s+/g, "-").toLowerCase() || "flow-matrix"}.csv`,
      [headers.join(","), ...rows].join("\n"),
      "csv",
    );
  };

  const triggerImport = () => importInputRef.current?.click();

  const importJson = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;

    try {
      const text = await file.text();
      const parsed = JSON.parse(text) as
        | Record<string, unknown>
        | Record<string, unknown>[];

      const importedMatrix =
        !Array.isArray(parsed) && Array.isArray(parsed.flows) ? parsed : null;
      const rawFlows = Array.isArray(parsed)
        ? parsed
        : Array.isArray(importedMatrix?.flows)
          ? importedMatrix.flows
          : [];
      const rawSections =
        importedMatrix && Array.isArray(importedMatrix.sections)
          ? (importedMatrix.sections as Record<string, unknown>[])
          : [];

      updateActiveMatrix((matrix) => {
        const nextSections = [...matrix.sections];
        const importedSectionIdMap = new Map<string, string>();

        rawSections.forEach((rawSection) => {
          const name = normalize(rawSection.name);
          if (!name) return;
          let section = nextSections.find(
            (item) => item.name.toLowerCase() === name.toLowerCase(),
          );
          if (!section) {
            section = createSection(name, nextSections.length);
            nextSections.push(section);
          }
          const rawId = normalize(rawSection.id);
          if (rawId) importedSectionIdMap.set(rawId, section.id);
        });

        const resolveSectionId = (
          rawSectionId: unknown,
          rawSectionName: unknown,
        ) => {
          const id = normalize(rawSectionId);
          if (id && importedSectionIdMap.has(id))
            return importedSectionIdMap.get(id) ?? null;

          const name = normalize(rawSectionName);
          if (!name) return null;
          const section = nextSections.find(
            (item) => item.name.toLowerCase() === name.toLowerCase(),
          );
          if (section) return section.id;

          const created = createSection(name, nextSections.length);
          nextSections.push(created);
          return created.id;
        };

        const importedFlows = rawFlows
          .map((rawFlow) => normalizeImportedFlow(rawFlow, resolveSectionId))
          .filter((flow): flow is Flow => flow !== null);

        return {
          ...matrix,
          sections: nextSections,
          flows: [...matrix.flows, ...importedFlows],
        };
      });
    } catch {
      window.alert("Import JSON impossible : fichier invalide.");
    }
  };

  const generateBulkAD = () => {
    pushHistory();
    const adFlows: Flow[] = [
      { application: "LDAP", protocol: "389/TCP" },
      { application: "KERBEROS", protocol: "88/TCP" },
      { application: "DNS", protocol: "53/UDP" },
    ].map((item) => ({
      id: genId(),
      ruleName: `ALLOW-${item.application}-AD`,
      source: "USERS",
      nomSource: "Utilisateurs",
      destination: "AD01",
      nomDestination: "Active Directory",
      application: item.application,
      protocol: item.protocol,
      action: "ALLOW",
      status: "PENDING",
      fromZone: "TRUST",
      toZone: "SERVERS",
      natSrc: "",
      natDst: "",
      comment: "Bulk AD",
      sectionId: null,
    }));

    updateActiveMatrix((matrix) => ({
      ...matrix,
      flows: [...matrix.flows, ...adFlows],
    }));
  };

  return (
    <main className="app-shell">
      <header className="brand-header">
        <div className="brand-lockup">
          <BrandMark />
          <div>
            <div className="brand-wordmark">TANCHI</div>
            <div className="brand-sub">Network &amp; Application Tools</div>
          </div>
        </div>

        <div className="header-actions">
          <div className="brand-product">
            <div className="brand-product-label">Tanchi Lab</div>
            <strong>Flow Matrix Designer</strong>
          </div>
        </div>
      </header>

      <div className="utility-dock" aria-label="Utilitaires rapides">
        <button
          className="utility-button utility-theme"
          onClick={() =>
            setTheme((current) => (current === "dark" ? "light" : "dark"))
          }
          aria-label="Basculer le thème"
          type="button"
        >
          <span className="theme-icon theme-icon-moon">☾</span>
          <span className="theme-icon theme-icon-sun">☀</span>
        </button>
        <button
          className="utility-button"
          onClick={() => setIsSettingsOpen(true)}
          aria-label="Ouvrir les paramètres"
          type="button"
        >
          ⚙
        </button>
      </div>

      <section className="card dashboard-card">
        <h5>Dashboard</h5>
        <div className="dashboard-grid">
          <div className="stat-card">
            Flux
            <h4>{stats.total}</h4>
          </div>
          <div className="stat-card">
            Allow
            <h4>{stats.allow}</h4>
          </div>
          <div className="stat-card">
            Deny
            <h4>{stats.deny}</h4>
          </div>
          <div className="stat-card">
            Conflits
            <h4>{stats.conflicts}</h4>
          </div>
        </div>
      </section>

      <div className="layout-row">
        <section className="panel-form sidebar-panel">
          {/* ── Navigation par onglets ── */}
          <div className="sidebar-tabs-bar">
            {(
              [
                {
                  id: "composer" as const,
                  icon: "+",
                  label: "Flux",
                  badge: null as number | null,
                },
                {
                  id: "sections" as const,
                  icon: "≡",
                  label: "Sections",
                  badge: null as number | null,
                },
                {
                  id: "bulk" as const,
                  icon: "⊟",
                  label: "Sélect",
                  badge:
                    selectedFlowIds.size > 0
                      ? selectedFlowIds.size
                      : (null as number | null),
                },
                {
                  id: "export" as const,
                  icon: "⇅",
                  label: "Export",
                  badge: null as number | null,
                },
                {
                  id: "config" as const,
                  icon: "{ }",
                  label: "Config",
                  badge: null as number | null,
                },
              ] as const
            ).map(({ id, icon, label, badge }) => (
              <button
                key={id}
                type="button"
                className={`sidebar-tab-btn${
                  toolboxTab === id ? " active" : ""
                }${badge ? " has-selection" : ""}`}
                onClick={() => setToolboxTab(id)}
                style={{ position: "relative" }}
              >
                <span className="sidebar-tab-icon">{icon}</span>
                <span className="sidebar-tab-label">{label}</span>
                {badge ? (
                  <span className="sidebar-tab-badge">{badge}</span>
                ) : null}
              </button>
            ))}
          </div>

          {/* ── Contenu actif ── */}
          <div className="sidebar-content">
            {/* ── Composer ── */}
            {toolboxTab === "composer" && (
              <div className="sidebar-card">
                <div className="sidebar-card-header">
                  <span>Nouveau flux</span>
                  <div style={{ display: "flex", gap: 4 }}>
                    <button
                      type="button"
                      className="btn btn-icon"
                      onClick={() => setIsObjectsModalOpen(true)}
                      title="Objets réseau"
                    >
                      ⊞
                    </button>
                    <button
                      type="button"
                      className="btn btn-icon"
                      onClick={swapSourceDestination}
                      title="Inverser Src ↔ Dst"
                    >
                      ⇅
                    </button>
                  </div>
                </div>

                <div className="form-grid compact-form">
                  <div className="field full-width">
                    <label htmlFor="ruleName">Rule Name</label>
                    <input
                      id="ruleName"
                      name="ruleName"
                      value={form.ruleName}
                      onChange={handleFormChange}
                      placeholder="ALLOW-LDAP-USERS"
                    />
                  </div>
                  <div className="field">
                    <label htmlFor="source">Source</label>
                    <input
                      id="source"
                      name="source"
                      value={form.source}
                      onChange={handleFormChange}
                      placeholder="USERS"
                      list="address-list"
                    />
                  </div>
                  <div className="field">
                    <label htmlFor="nomSource">Nom src</label>
                    <input
                      id="nomSource"
                      name="nomSource"
                      value={form.nomSource}
                      onChange={handleFormChange}
                      placeholder="optionnel"
                    />
                  </div>
                  <div className="field">
                    <label htmlFor="destination">Destination</label>
                    <input
                      id="destination"
                      name="destination"
                      value={form.destination}
                      onChange={handleFormChange}
                      placeholder="AD01"
                      list="address-list"
                    />
                  </div>
                  <div className="field">
                    <label htmlFor="nomDestination">Nom dst</label>
                    <input
                      id="nomDestination"
                      name="nomDestination"
                      value={form.nomDestination}
                      onChange={handleFormChange}
                      placeholder="optionnel"
                    />
                  </div>
                  <div className="field">
                    <label htmlFor="application">Application</label>
                    <input
                      id="application"
                      name="application"
                      list="application-list"
                      value={form.application}
                      onChange={handleFormChange}
                      placeholder="HTTPS, LDAP…"
                    />
                  </div>
                  <div className="field">
                    <label htmlFor="protocol">Protocole</label>
                    <input
                      id="protocol"
                      name="protocol"
                      value={form.protocol}
                      onChange={handleFormChange}
                      placeholder="443/TCP"
                      className={!protocolIsValid ? "invalid" : ""}
                    />
                  </div>
                  <div className="field">
                    <label htmlFor="action">Action</label>
                    <select
                      id="action"
                      name="action"
                      value={form.action}
                      onChange={handleFormChange}
                    >
                      <option value="ALLOW">ALLOW</option>
                      <option value="DENY">DENY</option>
                    </select>
                  </div>
                  <div className="field">
                    <label>Section</label>
                    <div className="inline-row">
                      <select
                        name="sectionId"
                        value={form.sectionId}
                        onChange={handleFormChange}
                        style={{ flex: 1, minWidth: 0 }}
                      >
                        <option value="">— aucune —</option>
                        {sections.map((s) => (
                          <option key={s.id} value={s.id}>
                            {s.name}
                          </option>
                        ))}
                      </select>
                      <button
                        type="button"
                        className="btn btn-square"
                        onClick={addSection}
                      >
                        +
                      </button>
                    </div>
                  </div>
                  <div className="field">
                    <label htmlFor="fromZone">Zone src</label>
                    <input
                      id="fromZone"
                      name="fromZone"
                      value={form.fromZone}
                      onChange={handleFormChange}
                    />
                  </div>
                  <div className="field">
                    <label htmlFor="toZone">Zone dst</label>
                    <input
                      id="toZone"
                      name="toZone"
                      value={form.toZone}
                      onChange={handleFormChange}
                    />
                  </div>
                  <div className="field">
                    <label htmlFor="natSrc">NAT src</label>
                    <input
                      id="natSrc"
                      name="natSrc"
                      value={form.natSrc}
                      onChange={handleFormChange}
                      placeholder="203.0.113.1"
                    />
                  </div>
                  <div className="field">
                    <label htmlFor="natDst">NAT dst</label>
                    <input
                      id="natDst"
                      name="natDst"
                      value={form.natDst}
                      onChange={handleFormChange}
                      placeholder="10.0.0.5:8080"
                    />
                  </div>
                  <div className="field full-width">
                    <label htmlFor="comment">Commentaire</label>
                    <textarea
                      id="comment"
                      name="comment"
                      rows={2}
                      value={form.comment}
                      onChange={handleFormChange}
                    />
                  </div>
                </div>

                <div className="button-stack compact-buttons">
                  <button
                    className="btn btn-primary"
                    type="button"
                    onClick={submitFlow}
                    disabled={!canSubmit}
                  >
                    {editingFlowId ? "Mettre à jour" : "Ajouter"}
                  </button>
                  {editingFlowId ? (
                    <button
                      className="btn btn-outline"
                      type="button"
                      onClick={resetForm}
                    >
                      Annuler
                    </button>
                  ) : null}
                </div>

                <datalist id="application-list">
                  {serviceOptions.map((item) => (
                    <option key={item} value={item} />
                  ))}
                </datalist>
                <datalist id="address-list">
                  {addressOptions.map((item) => (
                    <option key={item} value={item} />
                  ))}
                </datalist>
              </div>
            )}

            {/* ── Sections ── */}
            {toolboxTab === "sections" && (
              <div className="sidebar-card">
                <div className="sidebar-card-header">
                  <span>Sections</span>
                  <button
                    type="button"
                    className="btn btn-icon"
                    onClick={addSection}
                    title="Nouvelle section"
                  >
                    +
                  </button>
                </div>
                {sections.length ? (
                  <div className="section-list">
                    {sections.map((section) => {
                      const count = flows.filter(
                        (flow) => flow.sectionId === section.id,
                      ).length;
                      return (
                        <div key={section.id} className="section-item">
                          <span
                            className="section-dot"
                            style={{ background: section.color }}
                          />
                          <span className="section-name">{section.name}</span>
                          <span className="section-count">{count}</span>
                          <button
                            type="button"
                            className="btn btn-icon danger"
                            onClick={() => deleteSection(section.id)}
                          >
                            ✕
                          </button>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <div className="empty-state">Aucune section définie.</div>
                )}
              </div>
            )}

            {/* ── Export / Import ── */}
            {toolboxTab === "export" && (
              <div className="sidebar-card">
                <div className="sidebar-card-header">
                  <span>Import / Export</span>
                </div>
                <div className="button-stack" style={{ marginTop: 0 }}>
                  <button
                    className="btn btn-outline"
                    type="button"
                    onClick={triggerImport}
                  >
                    ↓&nbsp; Importer JSON
                  </button>
                  <button
                    className="btn btn-outline"
                    type="button"
                    onClick={exportJson}
                  >
                    ↑&nbsp; Exporter JSON
                  </button>
                  <button
                    className="btn btn-outline"
                    type="button"
                    onClick={exportCsv}
                  >
                    ↑&nbsp; Exporter CSV
                  </button>
                  <button
                    className="btn btn-outline-success"
                    type="button"
                    onClick={generateBulkAD}
                  >
                    ⚡&nbsp; Bulk AD
                  </button>
                </div>
                <input
                  ref={importInputRef}
                  type="file"
                  accept=".json,application/json"
                  hidden
                  onChange={importJson}
                />
                {exportFeedback ? (
                  <div className="export-feedback">{exportFeedback}</div>
                ) : null}
              </div>
            )}

            {/* ── Édition groupée ── */}
            {toolboxTab === "bulk" && (
              <div className="sidebar-card">
                <div className="sidebar-card-header">
                  <span>Édition groupée</span>
                  {selectedFlowIds.size > 0 && (
                    <span className="bulk-count-pill">
                      {selectedFlowIds.size} règle(s)
                    </span>
                  )}
                </div>

                {selectedFlowIds.size === 0 ? (
                  <div className="bulk-empty">
                    <div className="bulk-empty-icon">⊟</div>
                    <p>
                      Cochez des lignes dans le tableau pour activer l’édition
                      groupée.
                    </p>
                  </div>
                ) : (
                  <>
                    <div className="field">
                      <label>Champ à modifier</label>
                      <select
                        value={bulkField}
                        onChange={(e) => {
                          setBulkField(e.target.value);
                          setBulkValue("");
                        }}
                      >
                        <option value="action">Action</option>
                        <option value="status">Statut</option>
                        <option value="sectionId">Section</option>
                        <option value="fromZone">Zone source</option>
                        <option value="toZone">Zone destination</option>
                      </select>
                    </div>

                    <div className="field">
                      <label>Nouvelle valeur</label>
                      {bulkField === "action" && (
                        <select
                          value={bulkValue}
                          onChange={(e) => setBulkValue(e.target.value)}
                        >
                          <option value="ALLOW">ALLOW</option>
                          <option value="DENY">DENY</option>
                        </select>
                      )}
                      {bulkField === "status" && (
                        <select
                          value={bulkValue}
                          onChange={(e) => setBulkValue(e.target.value)}
                        >
                          <option value="PENDING">PENDING</option>
                          <option value="APPROVED">APPROUVÉ</option>
                          <option value="REJECTED">REFUSÉ</option>
                        </select>
                      )}
                      {bulkField === "sectionId" && (
                        <select
                          value={bulkValue}
                          onChange={(e) => setBulkValue(e.target.value)}
                        >
                          <option value="">— Sans section —</option>
                          {sections.map((s) => (
                            <option key={s.id} value={s.id}>
                              {s.name}
                            </option>
                          ))}
                        </select>
                      )}
                      {(bulkField === "fromZone" || bulkField === "toZone") && (
                        <input
                          value={bulkValue}
                          onChange={(e) => setBulkValue(e.target.value)}
                          placeholder="Ex: TRUST"
                        />
                      )}
                    </div>

                    <button
                      className="btn btn-primary"
                      type="button"
                      onClick={applyBulkEdit}
                    >
                      Appliquer aux {selectedFlowIds.size} règle(s)
                    </button>

                    <div className="bulk-divider" />

                    <button
                      className="btn btn-outline"
                      type="button"
                      onClick={bulkSwapSrcDst}
                    >
                      ⇅ Inverser Src ↔ Dst
                    </button>

                    <button
                      className="btn btn-outline"
                      type="button"
                      onClick={() => setSelectedFlowIds(new Set())}
                      style={{
                        color: "var(--danger)",
                        borderColor: "rgba(220,38,38,0.35)",
                      }}
                    >
                      ✕ Désélectionner tout
                    </button>
                  </>
                )}
              </div>
            )}

            {/* ── Config Juniper ── */}
            {toolboxTab === "config" && (
              <div className="sidebar-card sidebar-card-grow">
                <div className="sidebar-card-header">
                  <span>Config Juniper SRX</span>
                </div>
                <pre className="code-block sidebar-code">{juniperConfig}</pre>
              </div>
            )}
          </div>
          {/* end sidebar-content */}

          <div className="sidebar-status-bar">{saveStatusLabel}</div>
        </section>

        <section className="panel-matrix">
          <div className="matrix-tabs">
            {matrices.map((matrix) => (
              <div
                key={matrix.id}
                className={`matrix-tab ${matrix.id === activeMatrixId ? "active" : ""}`}
              >
                <button
                  type="button"
                  className="matrix-tab-main"
                  onClick={() => setActiveMatrixId(matrix.id)}
                >
                  {matrix.name}
                </button>
                {matrices.length > 1 ? (
                  <button
                    type="button"
                    className="matrix-tab-close"
                    onClick={() => deleteMatrix(matrix.id)}
                  >
                    ✕
                  </button>
                ) : null}
              </div>
            ))}
            <button
              type="button"
              className="matrix-tab-add"
              onClick={addMatrix}
            >
              +
            </button>
          </div>

          <div className="card card-block matrix-card">
            <div className="panel-head panel-head-wrap">
              <h5>Matrice</h5>
              <input
                className="table-search"
                value={tableQuery}
                onChange={(event) => setTableQuery(event.target.value)}
                placeholder="Rechercher dans les flux"
              />
            </div>

            <div className="flow-table-wrap">
              <table className="flow-table">
                <thead>
                  <tr>
                    <th className="col-check">
                      <input
                        type="checkbox"
                        className="flow-cb"
                        title="Tout sélectionner"
                        checked={
                          displayedFlows.length > 0 &&
                          displayedFlows.every((f) => selectedFlowIds.has(f.id))
                        }
                        onChange={(e) => {
                          if (e.target.checked)
                            setSelectedFlowIds(
                              new Set(displayedFlows.map((f) => f.id)),
                            );
                          else setSelectedFlowIds(new Set());
                          if (e.target.checked) setToolboxTab("bulk");
                        }}
                      />
                    </th>
                    <th>Rule Name</th>
                    <th>Src</th>
                    <th>Nom source</th>
                    <th>Dst</th>
                    <th>Nom destination</th>
                    <th>App</th>
                    <th>Port/Protocol</th>
                    <th>Action</th>
                    <th>Status</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {displayedFlows.length ? (
                    displayedFlows.map((flow, index) => {
                      const hasConflict = conflictKeys.has(
                        buildConflictKey(flow),
                      );
                      const section = sections.find(
                        (item) => item.id === flow.sectionId,
                      );
                      const flowIndex = flows.findIndex(
                        (item) => item.id === flow.id,
                      );

                      const isSelected = selectedFlowIds.has(flow.id);
                      return (
                        <tr
                          key={flow.id}
                          className={[
                            flow.status === "APPROVED" ? "approved-row" : "",
                            flow.status === "REJECTED" ? "rejected-row" : "",
                            hasConflict ? "conflict-row" : "",
                            isSelected ? "selected-row" : "",
                          ]
                            .filter(Boolean)
                            .join(" ")}
                          style={{
                            ["--section-color" as string]:
                              section?.color ?? "transparent",
                          }}
                        >
                          <td className="col-check">
                            <input
                              type="checkbox"
                              className="flow-cb"
                              checked={isSelected}
                              onChange={(e) => {
                                setSelectedFlowIds((prev) => {
                                  const next = new Set(prev);
                                  if (e.target.checked) {
                                    next.add(flow.id);
                                    setToolboxTab("bulk");
                                  } else next.delete(flow.id);
                                  return next;
                                });
                              }}
                            />
                            <span className="row-num">{index + 1}</span>
                          </td>
                          <td className="cell-muted">{flow.ruleName || "—"}</td>
                          <td>
                            {flow.source}
                            {flow.natSrc ? (
                              <div className="cell-subline">
                                → {flow.natSrc}
                              </div>
                            ) : null}
                          </td>
                          <td className="cell-muted">
                            {flow.nomSource || "—"}
                          </td>
                          <td>
                            {flow.destination}
                            {flow.natDst ? (
                              <div className="cell-subline">
                                → {flow.natDst}
                              </div>
                            ) : null}
                          </td>
                          <td className="cell-muted">
                            {flow.nomDestination || "—"}
                          </td>
                          <td>{flow.application || "—"}</td>
                          <td>{flow.protocol}</td>
                          <td>
                            <span
                              className={`action-text ${flow.action === "DENY" ? "deny" : "allow"}`}
                            >
                              {flow.action}
                            </span>
                          </td>
                          <td>
                            <div className="status-badges">
                              <span
                                className={`status-badge status-${flow.status.toLowerCase()}`}
                              >
                                {statusLabel(flow.status)}
                              </span>
                              {hasConflict ? (
                                <span className="conflict-badge">CONFLIT</span>
                              ) : null}
                            </div>
                          </td>
                          <td>
                            <div className="action-buttons">
                              <button
                                type="button"
                                className="btn btn-icon"
                                onClick={() => moveFlow(flow.id, "up")}
                                disabled={flowIndex <= 0}
                              >
                                ↑
                              </button>
                              <button
                                type="button"
                                className="btn btn-icon"
                                onClick={() => moveFlow(flow.id, "down")}
                                disabled={flowIndex >= flows.length - 1}
                              >
                                ↓
                              </button>
                              <button
                                type="button"
                                className="btn btn-icon success"
                                onClick={() =>
                                  updateFlowStatus(flow.id, "APPROVED")
                                }
                              >
                                ✓
                              </button>
                              <button
                                type="button"
                                className="btn btn-icon danger"
                                onClick={() =>
                                  updateFlowStatus(flow.id, "REJECTED")
                                }
                              >
                                ✕
                              </button>
                              <button
                                type="button"
                                className="btn btn-icon"
                                onClick={() => editFlow(flow)}
                              >
                                ✎
                              </button>
                              <button
                                type="button"
                                className="btn btn-icon"
                                onClick={() => duplicateFlow(flow.id)}
                              >
                                ⧉
                              </button>
                              <button
                                type="button"
                                className="btn btn-icon danger"
                                onClick={() => deleteFlow(flow.id)}
                              >
                                🗑
                              </button>
                            </div>
                          </td>
                        </tr>
                      );
                    })
                  ) : (
                    <tr>
                      <td colSpan={11} className="empty-row">
                        Aucun flux dans cette matrice.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          <div className="card card-block">
            <h5>Diagramme des flux</h5>

            <div className="diagram-legend">
              <span className="legend-pill">
                <span className="legend-dot legend-approved" />
                Validé
              </span>
              <span className="legend-pill">
                <span className="legend-dot legend-pending" />
                Pending
              </span>
              <span className="legend-pill">
                <span className="legend-dot legend-deny" />
                Deny
              </span>
              <span className="legend-pill">
                <span className="legend-dot legend-conflict" />
                Conflit
              </span>
            </div>

            <div className="diagram-controls">
              <div className="field">
                <label htmlFor="diagramQuery">Objet</label>
                <input
                  id="diagramQuery"
                  value={diagramQuery}
                  onChange={(event) => setDiagramQuery(event.target.value)}
                  placeholder="Filtrer source ou destination"
                />
              </div>
              <div className="field">
                <label htmlFor="diagramStatus">Statut</label>
                <select
                  id="diagramStatus"
                  value={diagramStatus}
                  onChange={(event) =>
                    setDiagramStatus(
                      event.target.value as "ACTIVE" | FlowStatus,
                    )
                  }
                >
                  <option value="ACTIVE">Actifs</option>
                  <option value="APPROVED">Validés</option>
                  <option value="PENDING">Pending</option>
                </select>
              </div>
              <div className="field">
                <label htmlFor="diagramAction">Action</label>
                <select
                  id="diagramAction"
                  value={diagramAction}
                  onChange={(event) =>
                    setDiagramAction(event.target.value as "ALL" | FlowAction)
                  }
                >
                  <option value="ALL">Toutes</option>
                  <option value="ALLOW">ALLOW</option>
                  <option value="DENY">DENY</option>
                </select>
              </div>
              <div className="field">
                <label htmlFor="diagramRelation">Lien</label>
                <select
                  id="diagramRelation"
                  value={selectedRelationKey}
                  onChange={(event) =>
                    setSelectedRelationKey(event.target.value)
                  }
                >
                  {relationGroups.length ? (
                    relationGroups.map((relation) => (
                      <option key={relation.key} value={relation.key}>
                        {relation.source} → {relation.destination} (
                        {relation.flows.length})
                      </option>
                    ))
                  ) : (
                    <option value="">Aucun lien</option>
                  )}
                </select>
              </div>
            </div>

            <div className="diagram-details">
              {selectedRelation ? (
                <>
                  <div className="diagram-details-title">
                    {selectedRelation.source} → {selectedRelation.destination}
                  </div>
                  <div className="diagram-details-summary">
                    {selectedRelation.flows.length} flux actif
                    {selectedRelation.flows.length > 1 ? "s" : ""}
                  </div>
                  <div className="diagram-flow-list">
                    {selectedRelation.flows.map((flow) => {
                      const hasConflict = conflictKeys.has(
                        buildConflictKey(flow),
                      );
                      return (
                        <div
                          key={flow.id}
                          className={`diagram-flow-item ${flow.status === "PENDING" ? "pending" : ""} ${flow.action === "DENY" ? "deny" : ""}`}
                        >
                          <div className="diagram-flow-title">
                            {flow.application || "Application libre"} —{" "}
                            {flow.protocol}
                          </div>
                          <div className="diagram-flow-meta">
                            {flow.status} | {flow.fromZone} → {flow.toZone} |{" "}
                            {flow.action}
                          </div>
                          {hasConflict ? (
                            <span className="conflict-badge">CONFLIT</span>
                          ) : null}
                          {flow.comment ? (
                            <div className="diagram-flow-comment">
                              {flow.comment}
                            </div>
                          ) : null}
                        </div>
                      );
                    })}
                  </div>
                </>
              ) : (
                <div className="empty-state">Aucun lien sélectionné.</div>
              )}
            </div>

            <div className="diagram-canvas">
              {relationGroups.length ? (
                <div className="diagram-board">
                  <svg
                    className="diagram-svg"
                    viewBox={`0 0 ${diagramGraph.width} ${diagramGraph.height}`}
                    role="img"
                    aria-label="Diagramme des flux"
                  >
                    <defs>
                      <linearGradient id="edgeSelected" x1="0" x2="1">
                        <stop offset="0%" stopColor="#34E1BC" />
                        <stop offset="100%" stopColor="#5B8CFF" />
                      </linearGradient>
                    </defs>

                    {relationGroups.map((relation) => {
                      const sourceNode = diagramGraph.nodeMap.get(
                        `source:${relation.source}`,
                      );
                      const destinationNode = diagramGraph.nodeMap.get(
                        `destination:${relation.destination}`,
                      );
                      if (!sourceNode || !destinationNode) return null;

                      const denyCount = relation.flows.filter(
                        (flow) => flow.action === "DENY",
                      ).length;
                      const approvedCount = relation.flows.filter(
                        (flow) => flow.status === "APPROVED",
                      ).length;
                      const isSelected = relation.key === selectedRelationKey;
                      const edgeColor = denyCount
                        ? "#dc2626"
                        : approvedCount === relation.flows.length
                          ? "#10b98e"
                          : "#8fa3bc";
                      const label = `${relation.flows.length} flux`;
                      const midX = (sourceNode.x + destinationNode.x) / 2;
                      const midY = (sourceNode.y + destinationNode.y) / 2;

                      return (
                        <g
                          key={relation.key}
                          className="diagram-edge-group"
                          onClick={() => setSelectedRelationKey(relation.key)}
                        >
                          <path
                            className={`diagram-edge ${isSelected ? "selected" : ""}`}
                            d={`M ${sourceNode.x + 110} ${sourceNode.y} C ${midX - 120} ${sourceNode.y}, ${midX + 120} ${destinationNode.y}, ${destinationNode.x - 110} ${destinationNode.y}`}
                            stroke={
                              isSelected ? "url(#edgeSelected)" : edgeColor
                            }
                          />
                          <rect
                            x={midX - 38}
                            y={midY - 15}
                            width="76"
                            height="30"
                            rx="15"
                            className={`diagram-edge-badge ${isSelected ? "selected" : ""}`}
                          />
                          <text
                            x={midX}
                            y={midY + 4}
                            textAnchor="middle"
                            className="diagram-edge-label"
                          >
                            {label}
                          </text>
                        </g>
                      );
                    })}

                    {diagramGraph.sourceNames.map((name) => {
                      const node = diagramGraph.nodeMap.get(`source:${name}`);
                      if (!node) return null;
                      const isActive = selectedRelation?.source === name;
                      return (
                        <g key={`source:${name}`}>
                          <rect
                            x={node.x - 110}
                            y={node.y - 26}
                            width="220"
                            height="52"
                            rx="18"
                            className={`diagram-node-box source ${isActive ? "active" : ""}`}
                          />
                          <text
                            x={node.x}
                            y={node.y + 5}
                            textAnchor="middle"
                            className="diagram-node-label"
                          >
                            {name}
                          </text>
                        </g>
                      );
                    })}

                    {diagramGraph.destinationNames.map((name) => {
                      const node = diagramGraph.nodeMap.get(
                        `destination:${name}`,
                      );
                      if (!node) return null;
                      const isActive = selectedRelation?.destination === name;
                      return (
                        <g key={`destination:${name}`}>
                          <rect
                            x={node.x - 110}
                            y={node.y - 26}
                            width="220"
                            height="52"
                            rx="18"
                            className={`diagram-node-box destination ${isActive ? "active" : ""}`}
                          />
                          <text
                            x={node.x}
                            y={node.y + 5}
                            textAnchor="middle"
                            className="diagram-node-label"
                          >
                            {name}
                          </text>
                        </g>
                      );
                    })}
                  </svg>
                </div>
              ) : (
                <div className="empty-state">
                  Aucun flux à afficher dans le diagramme.
                </div>
              )}
            </div>
          </div>
        </section>
      </div>

      {isSettingsOpen ? (
        <div className="modal-overlay" onClick={() => setIsSettingsOpen(false)}>
          <div
            className="modal-card settings-modal"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="modal-header">
              <div>
                <h5>Paramètres</h5>
                <div className="panel-subtitle">
                  Personnalisation, sauvegarde locale et utilitaires de travail.
                </div>
              </div>
              <button
                type="button"
                className="btn btn-icon"
                onClick={() => setIsSettingsOpen(false)}
              >
                ✕
              </button>
            </div>

            <div className="settings-grid">
              <div className="settings-card">
                <div className="settings-title">Apparence</div>
                <div className="settings-copy">
                  Choisissez le rendu visuel de l’interface.
                </div>
                <div className="settings-actions">
                  <button
                    type="button"
                    className={`btn ${theme === "light" ? "btn-primary" : "btn-outline"}`}
                    onClick={() => setTheme("light")}
                  >
                    Mode clair
                  </button>
                  <button
                    type="button"
                    className={`btn ${theme === "dark" ? "btn-primary" : "btn-outline"}`}
                    onClick={() => setTheme("dark")}
                  >
                    Mode sombre
                  </button>
                </div>
              </div>

              <div className="settings-card">
                <div className="settings-title">Sauvegarde locale</div>
                <div className="settings-copy">
                  Les matrices sont autosauvegardées sur cet appareil et
                  restaurées à la réouverture.
                </div>
                <div className="settings-meta">{saveStatusLabel}</div>
                <div className="settings-actions">
                  <button
                    type="button"
                    className="btn btn-primary"
                    onClick={saveWorkspaceNow}
                  >
                    Sauvegarder maintenant
                  </button>
                  <button
                    type="button"
                    className="btn btn-outline"
                    onClick={resetWorkspace}
                  >
                    Réinitialiser l’espace local
                  </button>
                </div>
              </div>

              <div className="settings-card">
                <div className="settings-title">Utilitaires</div>
                <div className="settings-copy">
                  Accès rapide aux opérations les plus utiles.
                </div>
                <div className="settings-actions settings-actions-stack">
                  <button
                    type="button"
                    className="btn btn-outline"
                    onClick={triggerImport}
                  >
                    Importer un JSON
                  </button>
                  <button
                    type="button"
                    className="btn btn-outline"
                    onClick={exportJson}
                  >
                    Exporter la matrice en JSON
                  </button>
                  <button
                    type="button"
                    className="btn btn-outline"
                    onClick={exportCsv}
                  >
                    Exporter la matrice en CSV
                  </button>
                  <button
                    type="button"
                    className="btn btn-outline"
                    onClick={generateBulkAD}
                  >
                    Générer le pack Bulk AD
                  </button>
                </div>
              </div>

              <div className="settings-card">
                <div className="settings-title">Raccourcis clavier</div>
                <div className="settings-copy">
                  Disponibles dans toute l’interface.
                </div>
                <div className="shortcuts-list">
                  {(
                    [
                      {
                        keys: ["Ctrl", "Z"],
                        desc: "Annuler la dernière action",
                      },
                      { keys: ["Ctrl", "S"], desc: "Sauvegarder maintenant" },
                      { keys: ["Ctrl", "C"], desc: "Copier la sélection" },
                      { keys: ["Ctrl", "V"], desc: "Coller" },
                      { keys: ["Ctrl", "A"], desc: "Tout sélectionner" },
                      { keys: ["Échap"], desc: "Annuler la saisie en cours" },
                      { keys: ["Entrée"], desc: "Valider le formulaire actif" },
                    ] as const
                  ).map(({ keys, desc }) => (
                    <div key={keys.join("+")} className="shortcut-item">
                      <div className="shortcut-keys">
                        {keys.map((k, i) => (
                          <span key={k}>
                            {i > 0 && <span className="shortcut-plus">+</span>}
                            <kbd className="shortcut-key">{k}</kbd>
                          </span>
                        ))}
                      </div>
                      <span className="shortcut-desc">{desc}</span>
                    </div>
                  ))}
                </div>
                <button
                  type="button"
                  className="btn btn-outline"
                  style={{ marginTop: 12 }}
                  onClick={undo}
                  disabled={flowsHistory.length === 0}
                >
                  ↩ Annuler
                  {flowsHistory.length > 0 ? ` (${flowsHistory.length})` : ""}
                </button>
              </div>

              <div className="settings-card credits-card">
                <div className="settings-title">Crédits</div>
                <div className="settings-copy">
                  Produit conçu pour l’écosystème Tanchi FlowMatrix.
                </div>
                <div className="credit-item">
                  <strong>Nuxs</strong>
                  <span>
                    Direction produit, design system et identité de l’outil.
                  </span>
                </div>
                <div className="credit-item">
                  <strong>TT</strong>
                  <span>
                    Support, retours terrain et contribution à l’expérience
                    utilisateur.
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      ) : null}

      {isObjectsModalOpen ? (
        <div
          className="modal-overlay"
          onClick={() => setIsObjectsModalOpen(false)}
        >
          <div
            className="modal-card objects-modal"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="modal-header">
              <div>
                <h5>Objets réseau</h5>
                <div className="panel-subtitle">
                  Références réutilisables pour les sources, destinations et
                  services.
                </div>
              </div>
              <button
                type="button"
                className="btn btn-icon"
                onClick={() => setIsObjectsModalOpen(false)}
              >
                ✕
              </button>
            </div>

            <div className="object-tabs">
              <button
                type="button"
                className={`object-tab ${objectTab === "addresses" ? "active" : ""}`}
                onClick={() => setObjectTab("addresses")}
              >
                Adresses <span>{objects.addresses.length}</span>
              </button>
              <button
                type="button"
                className={`object-tab ${objectTab === "services" ? "active" : ""}`}
                onClick={() => setObjectTab("services")}
              >
                Services <span>{objects.services.length}</span>
              </button>
            </div>

            {objectTab === "addresses" ? (
              <>
                <div className="object-list">
                  {objects.addresses.length ? (
                    objects.addresses.map((address) => (
                      <div key={address.id} className="object-item">
                        <div>
                          <div className="object-item-title">
                            {address.name}
                          </div>
                          <div className="object-item-meta">
                            {address.value}
                          </div>
                          {address.comment ? (
                            <div className="object-item-meta">
                              {address.comment}
                            </div>
                          ) : null}
                        </div>
                        <button
                          type="button"
                          className="btn btn-icon danger"
                          onClick={() => removeAddressObject(address.id)}
                        >
                          ✕
                        </button>
                      </div>
                    ))
                  ) : (
                    <div className="empty-state">
                      Aucune adresse enregistrée.
                    </div>
                  )}
                </div>

                <div className="object-form-grid">
                  <input
                    value={addressDraft.name}
                    onChange={(event) =>
                      setAddressDraft((current) => ({
                        ...current,
                        name: event.target.value,
                      }))
                    }
                    placeholder="Nom objet"
                  />
                  <input
                    value={addressDraft.value}
                    onChange={(event) =>
                      setAddressDraft((current) => ({
                        ...current,
                        value: event.target.value,
                      }))
                    }
                    placeholder="IP, CIDR ou hostname"
                  />
                  <input
                    className="object-form-full"
                    value={addressDraft.comment}
                    onChange={(event) =>
                      setAddressDraft((current) => ({
                        ...current,
                        comment: event.target.value,
                      }))
                    }
                    placeholder="Commentaire optionnel"
                  />
                </div>
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={addAddressObject}
                >
                  Ajouter l’adresse
                </button>
              </>
            ) : (
              <>
                <div className="object-list">
                  {objects.services.length ? (
                    objects.services.map((service) => (
                      <div key={service.id} className="object-item">
                        <div>
                          <div className="object-item-title">
                            {service.name}
                          </div>
                          <div className="object-item-meta">
                            {service.protocol || "—"}
                            {service.port ? ` · ${service.port}` : ""}
                          </div>
                          {service.comment ? (
                            <div className="object-item-meta">
                              {service.comment}
                            </div>
                          ) : null}
                        </div>
                        <button
                          type="button"
                          className="btn btn-icon danger"
                          onClick={() => removeServiceObject(service.id)}
                        >
                          ✕
                        </button>
                      </div>
                    ))
                  ) : (
                    <div className="empty-state">Aucun service enregistré.</div>
                  )}
                </div>

                <div className="object-form-grid">
                  <input
                    value={serviceDraft.name}
                    onChange={(event) =>
                      setServiceDraft((current) => ({
                        ...current,
                        name: event.target.value,
                      }))
                    }
                    placeholder="Nom service"
                  />
                  <input
                    value={serviceDraft.protocol}
                    onChange={(event) =>
                      setServiceDraft((current) => ({
                        ...current,
                        protocol: event.target.value,
                      }))
                    }
                    placeholder="443/TCP ou any"
                  />
                  <input
                    value={serviceDraft.port}
                    onChange={(event) =>
                      setServiceDraft((current) => ({
                        ...current,
                        port: event.target.value,
                      }))
                    }
                    placeholder="Port optionnel"
                  />
                  <input
                    value={serviceDraft.comment}
                    onChange={(event) =>
                      setServiceDraft((current) => ({
                        ...current,
                        comment: event.target.value,
                      }))
                    }
                    placeholder="Commentaire optionnel"
                  />
                </div>
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={addServiceObject}
                >
                  Ajouter le service
                </button>
              </>
            )}
          </div>
        </div>
      ) : null}
    </main>
  );
}

export default App;
