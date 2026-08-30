--
-- PostgreSQL database dump
--


-- Dumped from database version 17.6
-- Dumped by pg_dump version 17.10

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: public; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA IF NOT EXISTS public;


--
-- Name: SCHEMA public; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON SCHEMA public IS 'standard public schema';


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: activation_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.activation_events (
    id text NOT NULL,
    user_id uuid,
    event text NOT NULL,
    metadata jsonb,
    occurred_at timestamp with time zone DEFAULT now()
);


--
-- Name: agent_pubkeys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_pubkeys (
    agent_id text NOT NULL,
    public_key_pem text NOT NULL,
    registered_at timestamp with time zone DEFAULT now(),
    revoked_at timestamp with time zone,
    key_id text DEFAULT 'default'::text,
    key_version integer DEFAULT 1,
    rotated_from text,
    valid_from timestamp with time zone DEFAULT now(),
    valid_until timestamp with time zone,
    revocation_reason text,
    revoked_by text
);


--
-- Name: TABLE agent_pubkeys; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.agent_pubkeys IS 'Public key registry. Private keys never stored here.';


--
-- Name: active_agent_keys; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.active_agent_keys WITH (security_invoker='true') AS
 SELECT agent_id,
    key_id,
    key_version,
    public_key_pem,
    valid_from,
    valid_until,
    rotated_from,
    registered_at
   FROM public.agent_pubkeys
  WHERE ((revoked_at IS NULL) AND ((valid_until IS NULL) OR (valid_until > now())));


--
-- Name: admin_audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.admin_audit_log (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    actor_id uuid,
    actor_email text,
    action text NOT NULL,
    target_type text,
    target_id text,
    meta jsonb DEFAULT '{}'::jsonb,
    ip text,
    user_agent text,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: agent_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_policies (
    id text NOT NULL,
    agent_id text NOT NULL,
    name text NOT NULL,
    description text,
    condition text NOT NULL,
    action text DEFAULT 'flag'::text NOT NULL,
    message text,
    enabled boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: agents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agents (
    agent_id text NOT NULL,
    agent_name text NOT NULL,
    user_id uuid,
    public_key text,
    created_at timestamp with time zone DEFAULT now(),
    last_active timestamp with time zone,
    webhook_url text,
    webhook_secret text,
    retention_days integer,
    did_id text,
    did_public_key text,
    encrypted boolean DEFAULT false,
    key_id text,
    slack_channel text,
    api_key_hash text,
    key_hint text
);


--
-- Name: COLUMN agents.key_hint; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.agents.key_hint IS 'Masked display hint (e.g. dm_sk_ab12****cd34) for the dashboard. The plaintext api_key column it replaced was dropped in migration 012. Never used for authentication; that is api_key_hash.';


--
-- Name: app_state; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.app_state (
    key text NOT NULL,
    value text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: TABLE app_state; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.app_state IS 'Small server-side key/value state that must survive restarts. Not user data.';


--
-- Name: checkpoints; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.checkpoints (
    id bigint NOT NULL,
    "position" bigint NOT NULL,
    log_root text NOT NULL,
    tree_root text,
    server_sig text NOT NULL,
    "timestamp" timestamp with time zone NOT NULL,
    published boolean DEFAULT false,
    published_url text,
    created_at timestamp with time zone DEFAULT now(),
    tree_size bigint,
    checkpoint_id text,
    previous_cp_id text,
    previous_tree_root text,
    witness_count integer DEFAULT 0,
    witness_status text DEFAULT 'unwitnessed'::text
);


--
-- Name: TABLE checkpoints; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.checkpoints IS 'Periodic signed snapshots of log root. Published externally for independent verification.';


--
-- Name: COLUMN checkpoints.witness_status; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.checkpoints.witness_status IS 'unwitnessed | pending | witnessed | witness_failed';


--
-- Name: checkpoints_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.checkpoints_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: checkpoints_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.checkpoints_id_seq OWNED BY public.checkpoints.id;


--
-- Name: click_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.click_events (
    id bigint NOT NULL,
    source text NOT NULL,
    path text,
    user_agent text,
    referer text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: TABLE click_events; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.click_events IS 'Inbound marketing click attribution. Written by GET /go/:source. No PII stored.';


--
-- Name: click_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.click_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: click_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.click_events_id_seq OWNED BY public.click_events.id;


--
-- Name: commit_attachments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.commit_attachments (
    id text NOT NULL,
    commit_id text,
    type text NOT NULL,
    storage_provider text DEFAULT 'inline'::text,
    storage_bucket text,
    storage_key text,
    public_url text,
    mime_type text,
    size_bytes integer,
    filename text,
    language text,
    inline_content text,
    "position" integer,
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: commit_content; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.commit_content (
    id text NOT NULL,
    format text DEFAULT 'text'::text NOT NULL,
    text_content text,
    html_content text,
    prompt_text text,
    prompt_html text,
    token_count integer,
    char_count integer,
    has_images boolean DEFAULT false,
    has_code boolean DEFAULT false,
    has_tables boolean DEFAULT false,
    storage_provider text DEFAULT 'inline'::text,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: commit_usage; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.commit_usage (
    user_id uuid NOT NULL,
    month text NOT NULL,
    commit_count integer DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone DEFAULT now(),
    bytes_used bigint DEFAULT 0
);


--
-- Name: commits; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.commits (
    id text NOT NULL,
    from_agent text,
    to_agent text,
    context jsonb,
    signature text,
    verified boolean DEFAULT false,
    verification_reason text,
    "timestamp" timestamp with time zone,
    saved_at timestamp with time zone DEFAULT now(),
    schema_version text DEFAULT '1.0'::text,
    payload jsonb,
    event_type text DEFAULT 'commit'::text,
    parent_id text,
    trace_id text,
    branch_key text DEFAULT 'main'::text,
    agent_info jsonb,
    integrity_hash text,
    parent_hash text,
    fork_of text,
    fork_point text,
    lineage_root text,
    encrypted_payload text,
    key_id text,
    iv text,
    auth_tag text,
    did_signature text,
    payload_hash text,
    agent_id text,
    platform text,
    conv_id text,
    actor_role text,
    client_payload_hash text,
    client_integrity_hash text,
    agent_signature text,
    hash_mismatch boolean DEFAULT false,
    log_position bigint,
    leaf_hash text,
    tree_root_at_append text,
    tree_size_at_append bigint,
    checkpoint_id text,
    proof_status text DEFAULT 'pending'::text,
    client_timestamp timestamp with time zone,
    accepted_at timestamp with time zone,
    spec_version text DEFAULT '1.0'::text,
    capture_mode text DEFAULT 'client_signed'::text,
    assurance_level text DEFAULT 'L1'::text,
    client_signature text,
    client_public_key text,
    client_key_id text,
    client_signature_algorithm text,
    client_envelope_version text,
    client_metadata_hash text,
    client_envelope_hash text,
    client_attestation_ts timestamp with time zone,
    timestamp_skew_warning boolean DEFAULT false,
    metadata jsonb,
    client_attestation_ts_text text,
    completeness_claim boolean,
    client_attestation jsonb,
    CONSTRAINT commits_capture_mode_check CHECK ((capture_mode = ANY (ARRAY['client_signed'::text, 'proxy_forwarded'::text, 'proxy_stored'::text])))
);


--
-- Name: COLUMN commits.proof_status; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.commits.proof_status IS 'pending → included → checkpointed → checkpointed_published';


--
-- Name: COLUMN commits.client_timestamp; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.commits.client_timestamp IS 'Timestamp the agent asserted in the signed envelope. Part of the signed surface.';


--
-- Name: COLUMN commits.accepted_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.commits.accepted_at IS 'Timestamp the DarkMatter ledger accepted this commit. Set by server, not alterable by client.';


--
-- Name: conversation_threads; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.conversation_threads (
    id text NOT NULL,
    platform text NOT NULL,
    platform_url text,
    title text,
    user_id uuid,
    root_ctx_id text,
    tip_ctx_id text,
    turn_count integer DEFAULT 0,
    models_used text[],
    total_tokens integer DEFAULT 0,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: enterprise_accounts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.enterprise_accounts (
    id text NOT NULL,
    user_id uuid,
    company_name text NOT NULL,
    plan text DEFAULT 'enterprise'::text,
    byok_key_id text,
    byok_algorithm text DEFAULT 'aes-256-gcm'::text,
    tenant_schema text,
    did_document jsonb,
    created_at timestamp with time zone DEFAULT now(),
    active boolean DEFAULT true
);


--
-- Name: enterprise_inquiries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.enterprise_inquiries (
    id text NOT NULL,
    company_name text,
    name text,
    email text NOT NULL,
    use_case text,
    team_size text,
    features text[],
    message text,
    created_at timestamp with time zone DEFAULT now(),
    contacted boolean DEFAULT false
);


--
-- Name: enterprise_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.enterprise_keys (
    key_id text NOT NULL,
    account_id text,
    key_hint text,
    algorithm text DEFAULT 'aes-256-gcm'::text,
    created_at timestamp with time zone DEFAULT now(),
    rotated_at timestamp with time zone,
    active boolean DEFAULT true
);


--
-- Name: event_hooks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.event_hooks (
    id text NOT NULL,
    agent_id text,
    url text NOT NULL,
    secret text,
    events text[] NOT NULL,
    enabled boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now(),
    last_fired timestamp with time zone,
    failure_count integer DEFAULT 0
);


--
-- Name: feature_flags; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.feature_flags (
    key text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    updated_at timestamp with time zone DEFAULT now(),
    updated_by text
);


--
-- Name: hook_deliveries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.hook_deliveries (
    id text NOT NULL,
    hook_id text,
    event text NOT NULL,
    ctx_id text,
    status text,
    http_status integer,
    response text,
    duration_ms integer,
    attempted_at timestamp with time zone DEFAULT now()
);


--
-- Name: key_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.key_events (
    id bigint NOT NULL,
    agent_id text NOT NULL,
    key_id text NOT NULL,
    event_type text NOT NULL,
    previous_key_id text,
    reason text,
    performed_by text,
    "timestamp" timestamp with time zone DEFAULT now()
);


--
-- Name: TABLE key_events; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.key_events IS 'Immutable audit log of all key lifecycle events. Append-only.';


--
-- Name: COLUMN key_events.event_type; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.key_events.event_type IS 'registered | rotated | revoked | expired';


--
-- Name: key_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.key_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: key_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.key_events_id_seq OWNED BY public.key_events.id;


--
-- Name: latest_checkpoint; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.latest_checkpoint WITH (security_invoker='true') AS
 SELECT checkpoint_id,
    "position",
    tree_root,
    tree_size,
    log_root,
    server_sig,
    "timestamp",
    previous_cp_id,
    previous_tree_root,
    published,
    published_url,
    witness_count,
    witness_status
   FROM public.checkpoints
  ORDER BY "position" DESC
 LIMIT 1;


--
-- Name: log_entries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.log_entries (
    "position" bigint NOT NULL,
    commit_id text NOT NULL,
    integrity_hash text NOT NULL,
    log_root text NOT NULL,
    server_sig text NOT NULL,
    "timestamp" timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    leaf_hash text,
    tree_root text,
    tree_size bigint
);


--
-- Name: TABLE log_entries; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.log_entries IS 'Append-only log of commit integrity hashes. No UPDATE or DELETE policies — enforced by RLS.';


--
-- Name: COLUMN log_entries.leaf_hash; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.log_entries.leaf_hash IS 'RFC 6962 leaf hash: SHA256(0x00 || canonical(leaf_envelope))';


--
-- Name: COLUMN log_entries.tree_root; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.log_entries.tree_root IS 'Merkle tree root of log[0..position] at time of this append';


--
-- Name: log_entries_position_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.log_entries_position_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: log_entries_position_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.log_entries_position_seq OWNED BY public.log_entries."position";


--
-- Name: proxy_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.proxy_keys (
    id text DEFAULT ('pk_'::text || replace((gen_random_uuid())::text, '-'::text, ''::text)) NOT NULL,
    workspace_id text NOT NULL,
    member_id text NOT NULL,
    proxy_key text DEFAULT (('dmp_'::text || replace((gen_random_uuid())::text, '-'::text, ''::text)) || replace((gen_random_uuid())::text, '-'::text, ''::text)) NOT NULL,
    target_provider text DEFAULT 'openai'::text NOT NULL,
    encrypted_real_key text,
    real_key_hint text,
    label text,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone
);


--
-- Name: server_config; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.server_config (
    key text NOT NULL,
    value text NOT NULL,
    set_at timestamp with time zone DEFAULT now()
);


--
-- Name: shared_chains; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.shared_chains (
    id text NOT NULL,
    ctx_id text NOT NULL,
    created_by text,
    label text,
    expires_at timestamp with time zone,
    view_count integer DEFAULT 0,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: signing_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.signing_keys (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    key_id text NOT NULL,
    public_key text NOT NULL,
    algorithm text DEFAULT 'Ed25519'::text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    description text
);


--
-- Name: spec_versions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.spec_versions (
    version text NOT NULL,
    published_at timestamp with time zone DEFAULT now(),
    frozen_at timestamp with time zone,
    changelog text,
    spec_url text
);


--
-- Name: TABLE spec_versions; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.spec_versions IS 'Published integrity spec versions. Frozen versions are immutable.';


--
-- Name: subscriptions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.subscriptions (
    id text NOT NULL,
    user_id uuid NOT NULL,
    stripe_customer_id text NOT NULL,
    plan text DEFAULT 'free'::text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    current_period_start timestamp with time zone,
    current_period_end timestamp with time zone,
    cancel_at_period_end boolean DEFAULT false,
    stripe_price_id text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    commit_limit integer,
    retention_days integer
);


--
-- Name: user_recording_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_recording_keys (
    id text DEFAULT ((('urk_'::text || (EXTRACT(epoch FROM now()))::bigint) || '_'::text) || substr(md5((random())::text), 0, 8)) NOT NULL,
    user_id uuid,
    provider text NOT NULL,
    key_hint text NOT NULL,
    encrypted_key text,
    recording_enabled boolean DEFAULT true,
    label text,
    created_at timestamp with time zone DEFAULT now(),
    last_used_at timestamp with time zone
);


--
-- Name: webhook_deliveries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.webhook_deliveries (
    id text NOT NULL,
    agent_id text,
    commit_id text,
    webhook_url text NOT NULL,
    status text NOT NULL,
    http_status integer,
    response text,
    attempted_at timestamp with time zone DEFAULT now()
);


--
-- Name: witness_sigs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.witness_sigs (
    id bigint NOT NULL,
    checkpoint_id text NOT NULL,
    witness_id text NOT NULL,
    witness_sig text NOT NULL,
    witnessed_at timestamp with time zone NOT NULL,
    sig_valid boolean
);


--
-- Name: TABLE witness_sigs; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.witness_sigs IS 'Witness signature records — append-only by design';


--
-- Name: witness_sigs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.witness_sigs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: witness_sigs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.witness_sigs_id_seq OWNED BY public.witness_sigs.id;


--
-- Name: witnesses; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.witnesses (
    id bigint NOT NULL,
    witness_id text NOT NULL,
    name text NOT NULL,
    public_key_pem text NOT NULL,
    endpoint_url text,
    registered_at timestamp with time zone DEFAULT now(),
    active boolean DEFAULT true,
    deactivated_at timestamp with time zone,
    deactivation_reason text
);


--
-- Name: TABLE witnesses; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.witnesses IS 'External parties that independently co-sign DarkMatter checkpoints';


--
-- Name: witnesses_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.witnesses_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: witnesses_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.witnesses_id_seq OWNED BY public.witnesses.id;


--
-- Name: workspace_members; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.workspace_members (
    id text DEFAULT ('wm_'::text || replace((gen_random_uuid())::text, '-'::text, ''::text)) NOT NULL,
    workspace_id text NOT NULL,
    user_id uuid NOT NULL,
    email text NOT NULL,
    display_name text,
    role text DEFAULT 'member'::text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    agent_id text,
    joined_at timestamp with time zone DEFAULT now() NOT NULL,
    last_active timestamp with time zone
);


--
-- Name: workspace_commits; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.workspace_commits WITH (security_invoker='true') AS
 SELECT c.id,
    c.trace_id,
    c."timestamp",
    c.payload,
    c.integrity_hash,
    c.payload_hash,
    c.from_agent,
    c.agent_info,
    c.event_type,
    c.verified,
    wm.workspace_id,
    wm.email AS member_email,
    wm.display_name AS member_name,
    wm.role AS member_role,
    COALESCE((c.payload ->> '_source'::text), 'sdk'::text) AS capture_source
   FROM (public.commits c
     JOIN public.workspace_members wm ON (((c.from_agent = wm.agent_id) OR (c.agent_id = wm.agent_id))))
  WHERE (wm.workspace_id IS NOT NULL);


--
-- Name: workspace_daily_stats; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.workspace_daily_stats (
    workspace_id text NOT NULL,
    stat_date date NOT NULL,
    total_commits integer DEFAULT 0 NOT NULL,
    ext_commits integer DEFAULT 0 NOT NULL,
    proxy_commits integer DEFAULT 0 NOT NULL,
    members_active integer DEFAULT 0 NOT NULL,
    gaps_detected integer DEFAULT 0 NOT NULL
);


--
-- Name: workspace_invitations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.workspace_invitations (
    id text DEFAULT ('inv_'::text || replace((gen_random_uuid())::text, '-'::text, ''::text)) NOT NULL,
    workspace_id text NOT NULL,
    email text NOT NULL,
    role text DEFAULT 'member'::text NOT NULL,
    token text DEFAULT replace((gen_random_uuid())::text, '-'::text, ''::text) NOT NULL,
    invited_by uuid NOT NULL,
    accepted_at timestamp with time zone,
    expires_at timestamp with time zone DEFAULT (now() + '7 days'::interval) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: workspace_provider_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.workspace_provider_keys (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid,
    provider text NOT NULL,
    encrypted_key text NOT NULL,
    key_hint text,
    recording_enabled boolean DEFAULT true,
    label text,
    created_at timestamp with time zone DEFAULT now(),
    last_used_at timestamp with time zone
);


--
-- Name: workspaces; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.workspaces (
    id text DEFAULT ('ws_'::text || replace((gen_random_uuid())::text, '-'::text, ''::text)) NOT NULL,
    name text NOT NULL,
    owner_user_id uuid NOT NULL,
    join_code text DEFAULT upper("substring"(replace((gen_random_uuid())::text, '-'::text, ''::text), 1, 8)) NOT NULL,
    plan text DEFAULT 'team'::text NOT NULL,
    policy_can_delete boolean DEFAULT false NOT NULL,
    policy_capture_all boolean DEFAULT true NOT NULL,
    policy_allowed_llms text[] DEFAULT ARRAY['claude'::text, 'chatgpt'::text, 'grok'::text, 'gemini'::text, 'perplexity'::text] NOT NULL,
    policy_export_permission text DEFAULT 'admin'::text NOT NULL,
    policy_retention_days integer DEFAULT 90 NOT NULL,
    proxy_enabled boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: checkpoints id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.checkpoints ALTER COLUMN id SET DEFAULT nextval('public.checkpoints_id_seq'::regclass);


--
-- Name: click_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.click_events ALTER COLUMN id SET DEFAULT nextval('public.click_events_id_seq'::regclass);


--
-- Name: key_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.key_events ALTER COLUMN id SET DEFAULT nextval('public.key_events_id_seq'::regclass);


--
-- Name: log_entries position; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.log_entries ALTER COLUMN "position" SET DEFAULT nextval('public.log_entries_position_seq'::regclass);


--
-- Name: witness_sigs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.witness_sigs ALTER COLUMN id SET DEFAULT nextval('public.witness_sigs_id_seq'::regclass);


--
-- Name: witnesses id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.witnesses ALTER COLUMN id SET DEFAULT nextval('public.witnesses_id_seq'::regclass);


--
-- Name: activation_events activation_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.activation_events
    ADD CONSTRAINT activation_events_pkey PRIMARY KEY (id);


--
-- Name: admin_audit_log admin_audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_audit_log
    ADD CONSTRAINT admin_audit_log_pkey PRIMARY KEY (id);


--
-- Name: agent_policies agent_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_policies
    ADD CONSTRAINT agent_policies_pkey PRIMARY KEY (id);


--
-- Name: agent_pubkeys agent_pubkeys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_pubkeys
    ADD CONSTRAINT agent_pubkeys_pkey PRIMARY KEY (agent_id);


--
-- Name: agents agents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agents
    ADD CONSTRAINT agents_pkey PRIMARY KEY (agent_id);


--
-- Name: app_state app_state_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.app_state
    ADD CONSTRAINT app_state_pkey PRIMARY KEY (key);


--
-- Name: checkpoints checkpoints_checkpoint_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.checkpoints
    ADD CONSTRAINT checkpoints_checkpoint_id_key UNIQUE (checkpoint_id);


--
-- Name: checkpoints checkpoints_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.checkpoints
    ADD CONSTRAINT checkpoints_pkey PRIMARY KEY (id);


--
-- Name: click_events click_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.click_events
    ADD CONSTRAINT click_events_pkey PRIMARY KEY (id);


--
-- Name: commit_attachments commit_attachments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.commit_attachments
    ADD CONSTRAINT commit_attachments_pkey PRIMARY KEY (id);


--
-- Name: commit_content commit_content_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.commit_content
    ADD CONSTRAINT commit_content_pkey PRIMARY KEY (id);


--
-- Name: commit_usage commit_usage_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.commit_usage
    ADD CONSTRAINT commit_usage_pkey PRIMARY KEY (user_id, month);


--
-- Name: commits commits_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.commits
    ADD CONSTRAINT commits_pkey PRIMARY KEY (id);


--
-- Name: conversation_threads conversation_threads_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.conversation_threads
    ADD CONSTRAINT conversation_threads_pkey PRIMARY KEY (id);


--
-- Name: enterprise_accounts enterprise_accounts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enterprise_accounts
    ADD CONSTRAINT enterprise_accounts_pkey PRIMARY KEY (id);


--
-- Name: enterprise_inquiries enterprise_inquiries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enterprise_inquiries
    ADD CONSTRAINT enterprise_inquiries_pkey PRIMARY KEY (id);


--
-- Name: enterprise_keys enterprise_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enterprise_keys
    ADD CONSTRAINT enterprise_keys_pkey PRIMARY KEY (key_id);


--
-- Name: event_hooks event_hooks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_hooks
    ADD CONSTRAINT event_hooks_pkey PRIMARY KEY (id);


--
-- Name: feature_flags feature_flags_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.feature_flags
    ADD CONSTRAINT feature_flags_pkey PRIMARY KEY (key);


--
-- Name: hook_deliveries hook_deliveries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.hook_deliveries
    ADD CONSTRAINT hook_deliveries_pkey PRIMARY KEY (id);


--
-- Name: key_events key_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.key_events
    ADD CONSTRAINT key_events_pkey PRIMARY KEY (id);


--
-- Name: log_entries log_entries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.log_entries
    ADD CONSTRAINT log_entries_pkey PRIMARY KEY ("position");


--
-- Name: proxy_keys proxy_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.proxy_keys
    ADD CONSTRAINT proxy_keys_pkey PRIMARY KEY (id);


--
-- Name: proxy_keys proxy_keys_proxy_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.proxy_keys
    ADD CONSTRAINT proxy_keys_proxy_key_key UNIQUE (proxy_key);


--
-- Name: server_config server_config_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.server_config
    ADD CONSTRAINT server_config_pkey PRIMARY KEY (key);


--
-- Name: shared_chains shared_chains_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.shared_chains
    ADD CONSTRAINT shared_chains_pkey PRIMARY KEY (id);


--
-- Name: signing_keys signing_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.signing_keys
    ADD CONSTRAINT signing_keys_pkey PRIMARY KEY (id);


--
-- Name: spec_versions spec_versions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.spec_versions
    ADD CONSTRAINT spec_versions_pkey PRIMARY KEY (version);


--
-- Name: subscriptions subscriptions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subscriptions
    ADD CONSTRAINT subscriptions_pkey PRIMARY KEY (id);


--
-- Name: user_recording_keys user_recording_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_recording_keys
    ADD CONSTRAINT user_recording_keys_pkey PRIMARY KEY (id);


--
-- Name: webhook_deliveries webhook_deliveries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_deliveries
    ADD CONSTRAINT webhook_deliveries_pkey PRIMARY KEY (id);


--
-- Name: witness_sigs witness_sigs_checkpoint_id_witness_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.witness_sigs
    ADD CONSTRAINT witness_sigs_checkpoint_id_witness_id_key UNIQUE (checkpoint_id, witness_id);


--
-- Name: witness_sigs witness_sigs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.witness_sigs
    ADD CONSTRAINT witness_sigs_pkey PRIMARY KEY (id);


--
-- Name: witnesses witnesses_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.witnesses
    ADD CONSTRAINT witnesses_pkey PRIMARY KEY (id);


--
-- Name: witnesses witnesses_witness_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.witnesses
    ADD CONSTRAINT witnesses_witness_id_key UNIQUE (witness_id);


--
-- Name: workspace_daily_stats workspace_daily_stats_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_daily_stats
    ADD CONSTRAINT workspace_daily_stats_pkey PRIMARY KEY (workspace_id, stat_date);


--
-- Name: workspace_invitations workspace_invitations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_invitations
    ADD CONSTRAINT workspace_invitations_pkey PRIMARY KEY (id);


--
-- Name: workspace_invitations workspace_invitations_token_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_invitations
    ADD CONSTRAINT workspace_invitations_token_key UNIQUE (token);


--
-- Name: workspace_members workspace_members_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_members
    ADD CONSTRAINT workspace_members_pkey PRIMARY KEY (id);


--
-- Name: workspace_members workspace_members_workspace_id_user_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_members
    ADD CONSTRAINT workspace_members_workspace_id_user_id_key UNIQUE (workspace_id, user_id);


--
-- Name: workspace_provider_keys workspace_provider_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_provider_keys
    ADD CONSTRAINT workspace_provider_keys_pkey PRIMARY KEY (id);


--
-- Name: workspace_provider_keys workspace_provider_keys_user_id_provider_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_provider_keys
    ADD CONSTRAINT workspace_provider_keys_user_id_provider_key UNIQUE (user_id, provider);


--
-- Name: workspaces workspaces_join_code_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspaces
    ADD CONSTRAINT workspaces_join_code_key UNIQUE (join_code);


--
-- Name: workspaces workspaces_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspaces
    ADD CONSTRAINT workspaces_pkey PRIMARY KEY (id);


--
-- Name: activation_events_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX activation_events_user_idx ON public.activation_events USING btree (user_id, event);


--
-- Name: agent_policies_agent_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX agent_policies_agent_idx ON public.agent_policies USING btree (agent_id);


--
-- Name: agent_pubkeys_agent_time_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX agent_pubkeys_agent_time_idx ON public.agent_pubkeys USING btree (agent_id, valid_from, valid_until);


--
-- Name: agents_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX agents_user_idx ON public.agents USING btree (user_id);


--
-- Name: checkpoints_cp_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX checkpoints_cp_id_idx ON public.checkpoints USING btree (checkpoint_id);


--
-- Name: click_events_source_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX click_events_source_created_idx ON public.click_events USING btree (source, created_at DESC);


--
-- Name: commit_attachments_commit_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX commit_attachments_commit_idx ON public.commit_attachments USING btree (commit_id);


--
-- Name: commits_agent_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX commits_agent_id_idx ON public.commits USING btree (agent_id, "timestamp" DESC);


--
-- Name: commits_agent_ts_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX commits_agent_ts_idx ON public.commits USING btree (agent_id, "timestamp" DESC NULLS LAST) WHERE (agent_id IS NOT NULL);


--
-- Name: commits_assurance_level_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX commits_assurance_level_idx ON public.commits USING btree (assurance_level);


--
-- Name: commits_branch_key_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX commits_branch_key_idx ON public.commits USING btree (branch_key);


--
-- Name: commits_client_key_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX commits_client_key_id_idx ON public.commits USING btree (client_key_id);


--
-- Name: commits_conv_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX commits_conv_idx ON public.commits USING btree (conv_id);


--
-- Name: commits_fork_of_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX commits_fork_of_idx ON public.commits USING btree (fork_of);


--
-- Name: commits_fork_point_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX commits_fork_point_idx ON public.commits USING btree (fork_point);


--
-- Name: commits_from_agent_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX commits_from_agent_idx ON public.commits USING btree (from_agent);


--
-- Name: commits_from_agent_ts_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX commits_from_agent_ts_idx ON public.commits USING btree (from_agent, "timestamp" DESC);


--
-- Name: commits_integrity_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX commits_integrity_idx ON public.commits USING btree (integrity_hash);


--
-- Name: commits_key_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX commits_key_id_idx ON public.commits USING btree (key_id);


--
-- Name: commits_lineage_root_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX commits_lineage_root_idx ON public.commits USING btree (lineage_root);


--
-- Name: commits_log_position_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX commits_log_position_idx ON public.commits USING btree (log_position);


--
-- Name: commits_metadata_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX commits_metadata_idx ON public.commits USING gin (metadata) WHERE (metadata IS NOT NULL);


--
-- Name: commits_parent_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX commits_parent_id_idx ON public.commits USING btree (parent_id);


--
-- Name: commits_payload_hash_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX commits_payload_hash_idx ON public.commits USING btree (payload_hash);


--
-- Name: commits_platform_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX commits_platform_idx ON public.commits USING btree (agent_id, platform);


--
-- Name: commits_saved_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX commits_saved_at_idx ON public.commits USING btree (saved_at DESC);


--
-- Name: commits_to_agent_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX commits_to_agent_idx ON public.commits USING btree (to_agent, verified, "timestamp" DESC);


--
-- Name: commits_trace_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX commits_trace_id_idx ON public.commits USING btree (trace_id);


--
-- Name: commits_trace_ts_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX commits_trace_ts_idx ON public.commits USING btree (trace_id, "timestamp") WHERE (trace_id IS NOT NULL);


--
-- Name: conv_threads_platform_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX conv_threads_platform_idx ON public.conversation_threads USING btree (platform);


--
-- Name: conv_threads_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX conv_threads_user_idx ON public.conversation_threads USING btree (user_id, updated_at DESC);


--
-- Name: enterprise_accounts_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX enterprise_accounts_user_idx ON public.enterprise_accounts USING btree (user_id);


--
-- Name: enterprise_keys_account_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX enterprise_keys_account_idx ON public.enterprise_keys USING btree (account_id);


--
-- Name: event_hooks_agent_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX event_hooks_agent_idx ON public.event_hooks USING btree (agent_id, enabled);


--
-- Name: hook_deliveries_hook_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX hook_deliveries_hook_idx ON public.hook_deliveries USING btree (hook_id, attempted_at DESC);


--
-- Name: idx_agents_api_key_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agents_api_key_hash ON public.agents USING btree (api_key_hash);


--
-- Name: idx_proxy_keys_member; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_proxy_keys_member ON public.proxy_keys USING btree (member_id);


--
-- Name: idx_proxy_keys_proxy_key; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_proxy_keys_proxy_key ON public.proxy_keys USING btree (proxy_key);


--
-- Name: idx_proxy_keys_workspace; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_proxy_keys_workspace ON public.proxy_keys USING btree (workspace_id);


--
-- Name: idx_workspace_invitations_email; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workspace_invitations_email ON public.workspace_invitations USING btree (email);


--
-- Name: idx_workspace_invitations_token; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workspace_invitations_token ON public.workspace_invitations USING btree (token);


--
-- Name: idx_workspace_members_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workspace_members_agent ON public.workspace_members USING btree (agent_id);


--
-- Name: idx_workspace_members_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workspace_members_user ON public.workspace_members USING btree (user_id);


--
-- Name: idx_workspace_members_ws; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workspace_members_ws ON public.workspace_members USING btree (workspace_id);


--
-- Name: key_events_agent_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX key_events_agent_idx ON public.key_events USING btree (agent_id, "timestamp");


--
-- Name: log_entries_commit_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX log_entries_commit_idx ON public.log_entries USING btree (commit_id);


--
-- Name: log_entries_leaf_hash_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX log_entries_leaf_hash_idx ON public.log_entries USING btree (leaf_hash);


--
-- Name: log_entries_ts_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX log_entries_ts_idx ON public.log_entries USING btree ("timestamp" DESC);


--
-- Name: shared_chains_agent_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX shared_chains_agent_idx ON public.shared_chains USING btree (created_by);


--
-- Name: shared_chains_ctx_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX shared_chains_ctx_idx ON public.shared_chains USING btree (ctx_id);


--
-- Name: signing_keys_key_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX signing_keys_key_id_idx ON public.signing_keys USING btree (key_id);


--
-- Name: signing_keys_user_key_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX signing_keys_user_key_id_idx ON public.signing_keys USING btree (user_id, key_id);


--
-- Name: subscriptions_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX subscriptions_user_id_idx ON public.subscriptions USING btree (user_id);


--
-- Name: user_recording_keys_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX user_recording_keys_user_id ON public.user_recording_keys USING btree (user_id);


--
-- Name: webhook_deliveries_agent_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX webhook_deliveries_agent_idx ON public.webhook_deliveries USING btree (agent_id, attempted_at DESC);


--
-- Name: webhook_deliveries_commit_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX webhook_deliveries_commit_id_idx ON public.webhook_deliveries USING btree (commit_id);


--
-- Name: witness_sigs_cp_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX witness_sigs_cp_idx ON public.witness_sigs USING btree (checkpoint_id);


--
-- Name: witness_sigs_wit_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX witness_sigs_wit_idx ON public.witness_sigs USING btree (witness_id);


--
-- Name: activation_events activation_events_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.activation_events
    ADD CONSTRAINT activation_events_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;


--
-- Name: agent_policies agent_policies_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_policies
    ADD CONSTRAINT agent_policies_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE CASCADE;


--
-- Name: agent_pubkeys agent_pubkeys_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_pubkeys
    ADD CONSTRAINT agent_pubkeys_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id);


--
-- Name: agents agents_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agents
    ADD CONSTRAINT agents_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;


--
-- Name: commit_attachments commit_attachments_commit_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.commit_attachments
    ADD CONSTRAINT commit_attachments_commit_id_fkey FOREIGN KEY (commit_id) REFERENCES public.commits(id) ON DELETE CASCADE;


--
-- Name: commit_usage commit_usage_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.commit_usage
    ADD CONSTRAINT commit_usage_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;


--
-- Name: commits commits_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.commits
    ADD CONSTRAINT commits_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id);


--
-- Name: commits commits_fork_of_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.commits
    ADD CONSTRAINT commits_fork_of_fkey FOREIGN KEY (fork_of) REFERENCES public.commits(id);


--
-- Name: commits commits_fork_point_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.commits
    ADD CONSTRAINT commits_fork_point_fkey FOREIGN KEY (fork_point) REFERENCES public.commits(id);


--
-- Name: commits commits_from_agent_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.commits
    ADD CONSTRAINT commits_from_agent_fkey FOREIGN KEY (from_agent) REFERENCES public.agents(agent_id);


--
-- Name: commits commits_lineage_root_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.commits
    ADD CONSTRAINT commits_lineage_root_fkey FOREIGN KEY (lineage_root) REFERENCES public.commits(id);


--
-- Name: commits commits_parent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.commits
    ADD CONSTRAINT commits_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES public.commits(id);


--
-- Name: commits commits_to_agent_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.commits
    ADD CONSTRAINT commits_to_agent_fkey FOREIGN KEY (to_agent) REFERENCES public.agents(agent_id);


--
-- Name: conversation_threads conversation_threads_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.conversation_threads
    ADD CONSTRAINT conversation_threads_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;


--
-- Name: enterprise_accounts enterprise_accounts_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enterprise_accounts
    ADD CONSTRAINT enterprise_accounts_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;


--
-- Name: enterprise_keys enterprise_keys_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enterprise_keys
    ADD CONSTRAINT enterprise_keys_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.enterprise_accounts(id) ON DELETE CASCADE;


--
-- Name: event_hooks event_hooks_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_hooks
    ADD CONSTRAINT event_hooks_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE CASCADE;


--
-- Name: hook_deliveries hook_deliveries_hook_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.hook_deliveries
    ADD CONSTRAINT hook_deliveries_hook_id_fkey FOREIGN KEY (hook_id) REFERENCES public.event_hooks(id) ON DELETE CASCADE;


--
-- Name: log_entries log_entries_commit_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.log_entries
    ADD CONSTRAINT log_entries_commit_id_fkey FOREIGN KEY (commit_id) REFERENCES public.commits(id);


--
-- Name: proxy_keys proxy_keys_member_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.proxy_keys
    ADD CONSTRAINT proxy_keys_member_id_fkey FOREIGN KEY (member_id) REFERENCES public.workspace_members(id) ON DELETE CASCADE;


--
-- Name: proxy_keys proxy_keys_workspace_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.proxy_keys
    ADD CONSTRAINT proxy_keys_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: shared_chains shared_chains_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.shared_chains
    ADD CONSTRAINT shared_chains_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.agents(agent_id);


--
-- Name: signing_keys signing_keys_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.signing_keys
    ADD CONSTRAINT signing_keys_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;


--
-- Name: subscriptions subscriptions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subscriptions
    ADD CONSTRAINT subscriptions_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;


--
-- Name: user_recording_keys user_recording_keys_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_recording_keys
    ADD CONSTRAINT user_recording_keys_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;


--
-- Name: webhook_deliveries webhook_deliveries_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_deliveries
    ADD CONSTRAINT webhook_deliveries_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE CASCADE;


--
-- Name: webhook_deliveries webhook_deliveries_commit_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_deliveries
    ADD CONSTRAINT webhook_deliveries_commit_id_fkey FOREIGN KEY (commit_id) REFERENCES public.commits(id) ON DELETE CASCADE;


--
-- Name: witness_sigs witness_sigs_checkpoint_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.witness_sigs
    ADD CONSTRAINT witness_sigs_checkpoint_id_fkey FOREIGN KEY (checkpoint_id) REFERENCES public.checkpoints(checkpoint_id);


--
-- Name: witness_sigs witness_sigs_witness_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.witness_sigs
    ADD CONSTRAINT witness_sigs_witness_id_fkey FOREIGN KEY (witness_id) REFERENCES public.witnesses(witness_id);


--
-- Name: workspace_daily_stats workspace_daily_stats_workspace_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_daily_stats
    ADD CONSTRAINT workspace_daily_stats_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: workspace_invitations workspace_invitations_invited_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_invitations
    ADD CONSTRAINT workspace_invitations_invited_by_fkey FOREIGN KEY (invited_by) REFERENCES auth.users(id);


--
-- Name: workspace_invitations workspace_invitations_workspace_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_invitations
    ADD CONSTRAINT workspace_invitations_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: workspace_members workspace_members_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_members
    ADD CONSTRAINT workspace_members_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;


--
-- Name: workspace_members workspace_members_workspace_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_members
    ADD CONSTRAINT workspace_members_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: workspace_provider_keys workspace_provider_keys_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_provider_keys
    ADD CONSTRAINT workspace_provider_keys_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;


--
-- Name: workspaces workspaces_owner_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspaces
    ADD CONSTRAINT workspaces_owner_user_id_fkey FOREIGN KEY (owner_user_id) REFERENCES auth.users(id) ON DELETE CASCADE;


--
-- Name: shared_chains Create share links; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Create share links" ON public.shared_chains FOR INSERT WITH CHECK (((( SELECT auth.role() AS role) = 'service_role'::text) OR (created_by IN ( SELECT agents.agent_id
   FROM public.agents
  WHERE (agents.user_id = ( SELECT auth.uid() AS uid))))));


--
-- Name: shared_chains Manage own share links; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Manage own share links" ON public.shared_chains USING ((created_by IN ( SELECT agents.agent_id
   FROM public.agents
  WHERE (agents.user_id = ( SELECT auth.uid() AS uid))))) WITH CHECK ((created_by IN ( SELECT agents.agent_id
   FROM public.agents
  WHERE (agents.user_id = ( SELECT auth.uid() AS uid)))));


--
-- Name: shared_chains Read share links; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Read share links" ON public.shared_chains FOR SELECT USING (true);


--
-- Name: activation_events Service can insert activation events; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Service can insert activation events" ON public.activation_events FOR INSERT WITH CHECK ((( SELECT auth.role() AS role) = 'service_role'::text));


--
-- Name: hook_deliveries Service can insert hook deliveries; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Service can insert hook deliveries" ON public.hook_deliveries FOR INSERT WITH CHECK ((( SELECT auth.role() AS role) = 'service_role'::text));


--
-- Name: event_hooks Service role manages hooks; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Service role manages hooks" ON public.event_hooks AS RESTRICTIVE TO service_role USING (true) WITH CHECK (true);


--
-- Name: signing_keys Users can manage own signing keys; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can manage own signing keys" ON public.signing_keys USING ((auth.uid() = user_id)) WITH CHECK ((auth.uid() = user_id));


--
-- Name: subscriptions Users can read own subscription; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can read own subscription" ON public.subscriptions FOR SELECT USING ((auth.uid() = user_id));


--
-- Name: commit_usage Users can read own usage; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can read own usage" ON public.commit_usage FOR SELECT USING ((auth.uid() = user_id));


--
-- Name: event_hooks Users manage own hooks; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users manage own hooks" ON public.event_hooks USING ((agent_id IN ( SELECT agents.agent_id
   FROM public.agents
  WHERE (agents.user_id = ( SELECT auth.uid() AS uid))))) WITH CHECK ((agent_id IN ( SELECT agents.agent_id
   FROM public.agents
  WHERE (agents.user_id = ( SELECT auth.uid() AS uid)))));


--
-- Name: workspace_provider_keys Users manage own keys; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users manage own keys" ON public.workspace_provider_keys USING ((auth.uid() = user_id));


--
-- Name: agent_policies Users manage own policies; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users manage own policies" ON public.agent_policies USING ((agent_id IN ( SELECT agents.agent_id
   FROM public.agents
  WHERE (agents.user_id = ( SELECT auth.uid() AS uid)))));


--
-- Name: activation_events Users see own activation events; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users see own activation events" ON public.activation_events FOR SELECT USING ((user_id = ( SELECT auth.uid() AS uid)));


--
-- Name: commit_attachments Users see own attachments; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users see own attachments" ON public.commit_attachments USING ((commit_id IN ( SELECT c.id
   FROM (public.commits c
     JOIN public.agents a ON ((c.agent_id = a.agent_id)))
  WHERE (a.user_id = ( SELECT auth.uid() AS uid)))));


--
-- Name: commit_content Users see own content; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users see own content" ON public.commit_content USING ((id IN ( SELECT c.id
   FROM (public.commits c
     JOIN public.agents a ON ((c.agent_id = a.agent_id)))
  WHERE (a.user_id = ( SELECT auth.uid() AS uid)))));


--
-- Name: hook_deliveries Users see own hook deliveries; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users see own hook deliveries" ON public.hook_deliveries FOR SELECT USING ((hook_id IN ( SELECT h.id
   FROM (public.event_hooks h
     JOIN public.agents a ON ((h.agent_id = a.agent_id)))
  WHERE (a.user_id = ( SELECT auth.uid() AS uid)))));


--
-- Name: conversation_threads Users see own threads; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users see own threads" ON public.conversation_threads USING ((user_id = ( SELECT auth.uid() AS uid)));


--
-- Name: activation_events; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.activation_events ENABLE ROW LEVEL SECURITY;

--
-- Name: admin_audit_log; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.admin_audit_log ENABLE ROW LEVEL SECURITY;

--
-- Name: agent_policies; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.agent_policies ENABLE ROW LEVEL SECURITY;

--
-- Name: agent_pubkeys; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.agent_pubkeys ENABLE ROW LEVEL SECURITY;

--
-- Name: agent_pubkeys agent_pubkeys: agent sees own keys; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "agent_pubkeys: agent sees own keys" ON public.agent_pubkeys FOR SELECT USING ((agent_id = ((current_setting('request.jwt.claims'::text, true))::json ->> 'sub'::text)));


--
-- Name: agent_pubkeys agent_pubkeys: insert via service role; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "agent_pubkeys: insert via service role" ON public.agent_pubkeys FOR INSERT TO service_role WITH CHECK (true);


--
-- Name: agent_pubkeys agent_pubkeys: public read (pubkeys are public); Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "agent_pubkeys: public read (pubkeys are public)" ON public.agent_pubkeys FOR SELECT USING ((revoked_at IS NULL));


--
-- Name: agent_pubkeys agent_pubkeys: public read active keys; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "agent_pubkeys: public read active keys" ON public.agent_pubkeys FOR SELECT USING (((revoked_at IS NULL) AND ((valid_until IS NULL) OR (valid_until > now()))));


--
-- Name: agent_pubkeys agent_pubkeys: service role write; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "agent_pubkeys: service role write" ON public.agent_pubkeys TO service_role USING (true) WITH CHECK (true);


--
-- Name: agents; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.agents ENABLE ROW LEVEL SECURITY;

--
-- Name: app_state; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.app_state ENABLE ROW LEVEL SECURITY;

--
-- Name: checkpoints; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.checkpoints ENABLE ROW LEVEL SECURITY;

--
-- Name: checkpoints checkpoints: insert via service role; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "checkpoints: insert via service role" ON public.checkpoints FOR INSERT TO service_role WITH CHECK (true);


--
-- Name: checkpoints checkpoints: public read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "checkpoints: public read" ON public.checkpoints FOR SELECT USING (true);


--
-- Name: checkpoints checkpoints: update via service role; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "checkpoints: update via service role" ON public.checkpoints FOR UPDATE TO service_role USING (true);


--
-- Name: click_events; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.click_events ENABLE ROW LEVEL SECURITY;

--
-- Name: commit_attachments; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.commit_attachments ENABLE ROW LEVEL SECURITY;

--
-- Name: commit_content; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.commit_content ENABLE ROW LEVEL SECURITY;

--
-- Name: commit_usage; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.commit_usage ENABLE ROW LEVEL SECURITY;

--
-- Name: commits; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.commits ENABLE ROW LEVEL SECURITY;

--
-- Name: conversation_threads; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.conversation_threads ENABLE ROW LEVEL SECURITY;

--
-- Name: enterprise_accounts; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.enterprise_accounts ENABLE ROW LEVEL SECURITY;

--
-- Name: enterprise_inquiries; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.enterprise_inquiries ENABLE ROW LEVEL SECURITY;

--
-- Name: enterprise_keys; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.enterprise_keys ENABLE ROW LEVEL SECURITY;

--
-- Name: event_hooks; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.event_hooks ENABLE ROW LEVEL SECURITY;

--
-- Name: feature_flags; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.feature_flags ENABLE ROW LEVEL SECURITY;

--
-- Name: hook_deliveries; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.hook_deliveries ENABLE ROW LEVEL SECURITY;

--
-- Name: workspace_invitations inv: admin manages; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "inv: admin manages" ON public.workspace_invitations USING ((workspace_id IN ( SELECT workspace_members.workspace_id
   FROM public.workspace_members
  WHERE ((workspace_members.user_id = auth.uid()) AND (workspace_members.role = 'admin'::text)))));


--
-- Name: key_events; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.key_events ENABLE ROW LEVEL SECURITY;

--
-- Name: key_events key_events: insert via service role; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "key_events: insert via service role" ON public.key_events FOR INSERT TO service_role WITH CHECK (true);


--
-- Name: key_events key_events: public read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "key_events: public read" ON public.key_events FOR SELECT USING (true);


--
-- Name: log_entries; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.log_entries ENABLE ROW LEVEL SECURITY;

--
-- Name: log_entries log_entries: insert only via service role; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "log_entries: insert only via service role" ON public.log_entries FOR INSERT TO service_role WITH CHECK (true);


--
-- Name: log_entries log_entries: public read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "log_entries: public read" ON public.log_entries FOR SELECT USING (true);


--
-- Name: proxy_keys pk: admin reads all; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "pk: admin reads all" ON public.proxy_keys FOR SELECT USING ((workspace_id IN ( SELECT workspace_members.workspace_id
   FROM public.workspace_members
  WHERE ((workspace_members.user_id = auth.uid()) AND (workspace_members.role = 'admin'::text)))));


--
-- Name: proxy_keys pk: member reads own; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "pk: member reads own" ON public.proxy_keys FOR SELECT USING ((member_id IN ( SELECT workspace_members.id
   FROM public.workspace_members
  WHERE (workspace_members.user_id = auth.uid()))));


--
-- Name: proxy_keys pk: service role write; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "pk: service role write" ON public.proxy_keys TO service_role USING (true) WITH CHECK (true);


--
-- Name: proxy_keys; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.proxy_keys ENABLE ROW LEVEL SECURITY;

--
-- Name: server_config; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.server_config ENABLE ROW LEVEL SECURITY;

--
-- Name: server_config server_config: service role only; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "server_config: service role only" ON public.server_config TO service_role USING (true);


--
-- Name: commits service can insert commits; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "service can insert commits" ON public.commits FOR INSERT WITH CHECK ((( SELECT auth.role() AS role) = 'service_role'::text));


--
-- Name: webhook_deliveries service can insert webhook deliveries; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "service can insert webhook deliveries" ON public.webhook_deliveries FOR INSERT WITH CHECK ((( SELECT auth.role() AS role) = 'service_role'::text));


--
-- Name: enterprise_keys service manages enterprise keys; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "service manages enterprise keys" ON public.enterprise_keys USING ((( SELECT auth.role() AS role) = 'service_role'::text)) WITH CHECK ((( SELECT auth.role() AS role) = 'service_role'::text));


--
-- Name: enterprise_inquiries service manages inquiries; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "service manages inquiries" ON public.enterprise_inquiries FOR INSERT WITH CHECK ((( SELECT auth.role() AS role) = 'service_role'::text));


--
-- Name: admin_audit_log service role bypass; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "service role bypass" ON public.admin_audit_log TO service_role USING (true) WITH CHECK (true);


--
-- Name: commits service role bypass; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "service role bypass" ON public.commits TO service_role USING (true) WITH CHECK (true);


--
-- Name: feature_flags service role bypass; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "service role bypass" ON public.feature_flags TO service_role USING (true) WITH CHECK (true);


--
-- Name: subscriptions service role bypass; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "service role bypass" ON public.subscriptions TO service_role USING (true) WITH CHECK (true);


--
-- Name: shared_chains; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.shared_chains ENABLE ROW LEVEL SECURITY;

--
-- Name: signing_keys; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.signing_keys ENABLE ROW LEVEL SECURITY;

--
-- Name: spec_versions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.spec_versions ENABLE ROW LEVEL SECURITY;

--
-- Name: spec_versions spec_versions: public read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "spec_versions: public read" ON public.spec_versions FOR SELECT USING (true);


--
-- Name: spec_versions spec_versions: service role write; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "spec_versions: service role write" ON public.spec_versions TO service_role USING (true) WITH CHECK (true);


--
-- Name: workspace_daily_stats stats: service role write; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "stats: service role write" ON public.workspace_daily_stats TO service_role USING (true) WITH CHECK (true);


--
-- Name: workspace_daily_stats stats: workspace members read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "stats: workspace members read" ON public.workspace_daily_stats FOR SELECT USING ((workspace_id IN ( SELECT workspace_members.workspace_id
   FROM public.workspace_members
  WHERE (workspace_members.user_id = auth.uid()))));


--
-- Name: subscriptions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.subscriptions ENABLE ROW LEVEL SECURITY;

--
-- Name: user_recording_keys; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.user_recording_keys ENABLE ROW LEVEL SECURITY;

--
-- Name: user_recording_keys user_recording_keys_own; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY user_recording_keys_own ON public.user_recording_keys TO authenticated USING ((user_id = auth.uid())) WITH CHECK ((user_id = auth.uid()));


--
-- Name: user_recording_keys user_recording_keys_service; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY user_recording_keys_service ON public.user_recording_keys TO service_role USING (true) WITH CHECK (true);


--
-- Name: agents users manage own agents; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "users manage own agents" ON public.agents USING ((user_id = ( SELECT auth.uid() AS uid)));


--
-- Name: commits users see own commits; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "users see own commits" ON public.commits FOR SELECT USING (((from_agent IN ( SELECT agents.agent_id
   FROM public.agents
  WHERE (agents.user_id = ( SELECT auth.uid() AS uid)))) OR (to_agent IN ( SELECT agents.agent_id
   FROM public.agents
  WHERE (agents.user_id = ( SELECT auth.uid() AS uid))))));


--
-- Name: enterprise_accounts users see own enterprise account; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "users see own enterprise account" ON public.enterprise_accounts USING ((user_id = ( SELECT auth.uid() AS uid)));


--
-- Name: webhook_deliveries users see own webhook deliveries; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "users see own webhook deliveries" ON public.webhook_deliveries FOR SELECT USING ((agent_id IN ( SELECT agents.agent_id
   FROM public.agents
  WHERE (agents.user_id = ( SELECT auth.uid() AS uid)))));


--
-- Name: webhook_deliveries; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.webhook_deliveries ENABLE ROW LEVEL SECURITY;

--
-- Name: witness_sigs; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.witness_sigs ENABLE ROW LEVEL SECURITY;

--
-- Name: witness_sigs witness_sigs: insert via service; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "witness_sigs: insert via service" ON public.witness_sigs FOR INSERT TO service_role WITH CHECK (true);


--
-- Name: witness_sigs witness_sigs: public read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "witness_sigs: public read" ON public.witness_sigs FOR SELECT USING (true);


--
-- Name: witness_sigs witness_sigs: update via service; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "witness_sigs: update via service" ON public.witness_sigs FOR UPDATE TO service_role USING (true);


--
-- Name: witnesses; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.witnesses ENABLE ROW LEVEL SECURITY;

--
-- Name: witnesses witnesses: insert via service role; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "witnesses: insert via service role" ON public.witnesses FOR INSERT TO service_role WITH CHECK (true);


--
-- Name: witnesses witnesses: public read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "witnesses: public read" ON public.witnesses FOR SELECT USING ((active = true));


--
-- Name: witnesses witnesses: update via service role; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "witnesses: update via service role" ON public.witnesses FOR UPDATE TO service_role USING (true);


--
-- Name: workspace_members wm: admin reads all; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "wm: admin reads all" ON public.workspace_members FOR SELECT USING ((workspace_id IN ( SELECT workspace_members_1.workspace_id
   FROM public.workspace_members workspace_members_1
  WHERE ((workspace_members_1.user_id = auth.uid()) AND (workspace_members_1.role = 'admin'::text)))));


--
-- Name: workspace_members wm: member reads own; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "wm: member reads own" ON public.workspace_members FOR SELECT USING ((user_id = auth.uid()));


--
-- Name: workspace_members wm: service role write; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "wm: service role write" ON public.workspace_members TO service_role USING (true) WITH CHECK (true);


--
-- Name: workspaces workspace: members can read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "workspace: members can read" ON public.workspaces FOR SELECT USING ((id IN ( SELECT workspace_members.workspace_id
   FROM public.workspace_members
  WHERE (workspace_members.user_id = auth.uid()))));


--
-- Name: workspaces workspace: owner full access; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "workspace: owner full access" ON public.workspaces USING ((owner_user_id = auth.uid()));


--
-- Name: workspace_daily_stats; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.workspace_daily_stats ENABLE ROW LEVEL SECURITY;

--
-- Name: workspace_invitations; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.workspace_invitations ENABLE ROW LEVEL SECURITY;

--
-- Name: workspace_members; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.workspace_members ENABLE ROW LEVEL SECURITY;

--
-- Name: workspace_provider_keys; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.workspace_provider_keys ENABLE ROW LEVEL SECURITY;

--
-- Name: workspaces; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.workspaces ENABLE ROW LEVEL SECURITY;

--
-- PostgreSQL database dump complete
--


