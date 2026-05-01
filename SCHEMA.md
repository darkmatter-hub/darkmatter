# DarkMatter — Supabase Schema Reference
# Generated from information_schema.columns, public schema
# Use this as the source of truth for all DB queries

## Orphaned tables (in DB, not used in code)
- agent_policies — policy engine not yet implemented
- agent_pubkeys — superseded by signing_keys
- commit_usage — exists but not wired up (being fixed)
- key_events — key rotation audit log, not yet read
- server_config — unused
- signing_keys — L3 verification uses agent_pubkeys instead
- spec_versions — spec versioning not yet implemented
- webhook_deliveries — duplicate of hook_deliveries

## Views (not base tables)
- active_agent_keys — view over agent_pubkeys
- latest_checkpoint — view over checkpoints
- workspace_commits — join view of commits + workspace_members

## Missing columns (referenced in code, not in schema dump)
- subscriptions.commit_limit — per-subscription cap override (integer, nullable); app falls back to PLAN_META when NULL
- subscriptions.retention_days — per-subscription retention override (integer, nullable); app falls back to PLAN_META when NULL
- Run: ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS commit_limit integer, ADD COLUMN IF NOT EXISTS retention_days integer;

## Tables

### activation_events
| column | type | nullable |
|--------|------|----------|
| id | text | NO |
| user_id | uuid | YES |
| event | text | NO |
| metadata | jsonb | YES |
| occurred_at | timestamptz | YES |

### active_agent_keys (view)
| column | type | nullable |
|--------|------|----------|
| agent_id | text | YES |
| key_id | text | YES |
| key_version | integer | YES |
| public_key_pem | text | YES |
| valid_from | timestamptz | YES |
| valid_until | timestamptz | YES |
| rotated_from | text | YES |
| registered_at | timestamptz | YES |

### admin_audit_log
| column | type | nullable |
|--------|------|----------|
| id | uuid | NO |
| actor_id | uuid | YES |
| actor_email | text | YES |
| action | text | NO |
| target_type | text | YES |
| target_id | text | YES |
| meta | jsonb | YES |
| ip | text | YES |
| user_agent | text | YES |
| created_at | timestamptz | YES |

### agent_policies
| column | type | nullable |
|--------|------|----------|
| id | text | NO |
| agent_id | text | NO |
| name | text | NO |
| description | text | YES |
| condition | text | NO |
| action | text | NO |
| message | text | YES |
| enabled | boolean | YES |
| created_at | timestamptz | YES |

### agent_pubkeys
| column | type | nullable |
|--------|------|----------|
| agent_id | text | NO |
| public_key_pem | text | NO |
| registered_at | timestamptz | YES |
| revoked_at | timestamptz | YES |
| key_id | text | YES |
| key_version | integer | YES |
| rotated_from | text | YES |
| valid_from | timestamptz | YES |
| valid_until | timestamptz | YES |
| revocation_reason | text | YES |
| revoked_by | text | YES |

### agents
| column | type | nullable |
|--------|------|----------|
| agent_id | text | NO |
| agent_name | text | NO |
| user_id | uuid | YES |
| api_key | text | NO |
| public_key | text | YES |
| created_at | timestamptz | YES |
| last_active | timestamptz | YES |
| webhook_url | text | YES |
| webhook_secret | text | YES |
| retention_days | integer | YES |
| did_id | text | YES |
| did_public_key | text | YES |
| encrypted | boolean | YES |
| key_id | text | YES |
| slack_channel | text | YES |

### checkpoints
| column | type | nullable |
|--------|------|----------|
| id | bigint | NO |
| position | bigint | NO |
| log_root | text | NO |
| tree_root | text | YES |
| server_sig | text | NO |
| timestamp | timestamptz | NO |
| published | boolean | YES |
| published_url | text | YES |
| created_at | timestamptz | YES |
| tree_size | bigint | YES |
| checkpoint_id | text | YES |
| previous_cp_id | text | YES |
| previous_tree_root | text | YES |
| witness_count | integer | YES |
| witness_status | text | YES |

### commit_attachments
| column | type | nullable |
|--------|------|----------|
| id | text | NO |
| commit_id | text | YES |
| type | text | NO |
| storage_provider | text | YES |
| storage_bucket | text | YES |
| storage_key | text | YES |
| public_url | text | YES |
| mime_type | text | YES |
| size_bytes | integer | YES |
| filename | text | YES |
| language | text | YES |
| inline_content | text | YES |
| position | integer | YES |
| metadata | jsonb | YES |
| created_at | timestamptz | YES |

### commit_content
| column | type | nullable |
|--------|------|----------|
| id | text | NO |
| format | text | NO |
| text_content | text | YES |
| html_content | text | YES |
| prompt_text | text | YES |
| prompt_html | text | YES |
| token_count | integer | YES |
| char_count | integer | YES |
| has_images | boolean | YES |
| has_code | boolean | YES |
| has_tables | boolean | YES |
| storage_provider | text | YES |
| created_at | timestamptz | YES |

### commit_usage
| column | type | nullable |
|--------|------|----------|
| user_id | uuid | NO |
| month | text | NO |
| commit_count | integer | NO |
| updated_at | timestamptz | YES |

### commits
| column | type | nullable |
|--------|------|----------|
| id | text | NO |
| from_agent | text | YES |
| to_agent | text | YES |
| context | jsonb | YES |
| signature | text | YES |
| verified | boolean | YES |
| verification_reason | text | YES |
| timestamp | timestamptz | YES |
| saved_at | timestamptz | YES |
| schema_version | text | YES |
| payload | jsonb | YES |
| event_type | text | YES |
| parent_id | text | YES |
| trace_id | text | YES |
| branch_key | text | YES |
| agent_info | jsonb | YES |
| integrity_hash | text | YES |
| parent_hash | text | YES |
| fork_of | text | YES |
| fork_point | text | YES |
| lineage_root | text | YES |
| encrypted_payload | text | YES |
| key_id | text | YES |
| iv | text | YES |
| auth_tag | text | YES |
| did_signature | text | YES |
| payload_hash | text | YES |
| agent_id | text | YES |
| platform | text | YES |
| conv_id | text | YES |
| actor_role | text | YES |
| client_payload_hash | text | YES |
| client_integrity_hash | text | YES |
| agent_signature | text | YES |
| hash_mismatch | boolean | YES |
| log_position | bigint | YES |
| leaf_hash | text | YES |
| tree_root_at_append | text | YES |
| tree_size_at_append | bigint | YES |
| checkpoint_id | text | YES |
| proof_status | text | YES |
| client_timestamp | timestamptz | YES |
| accepted_at | timestamptz | YES |
| spec_version | text | YES |
| capture_mode | text | YES |
| assurance_level | text | YES |
| client_signature | text | YES |
| client_public_key | text | YES |
| client_key_id | text | YES |
| client_signature_algorithm | text | YES |
| client_envelope_version | text | YES |
| client_metadata_hash | text | YES |
| client_envelope_hash | text | YES |
| client_attestation_ts | timestamptz | YES |
| timestamp_skew_warning | boolean | YES |
| metadata | jsonb | YES |
| client_attestation_ts_text | text | YES |
| completeness_claim | boolean | YES |
| client_attestation | jsonb | YES |

### conversation_threads
| column | type | nullable |
|--------|------|----------|
| id | text | NO |
| platform | text | NO |
| platform_url | text | YES |
| title | text | YES |
| user_id | uuid | YES |
| root_ctx_id | text | YES |
| tip_ctx_id | text | YES |
| turn_count | integer | YES |
| models_used | ARRAY | YES |
| total_tokens | integer | YES |
| created_at | timestamptz | YES |
| updated_at | timestamptz | YES |

### enterprise_accounts
| column | type | nullable |
|--------|------|----------|
| id | text | NO |
| user_id | uuid | YES |
| company_name | text | NO |
| plan | text | YES |
| byok_key_id | text | YES |
| byok_algorithm | text | YES |
| tenant_schema | text | YES |
| did_document | jsonb | YES |
| created_at | timestamptz | YES |
| active | boolean | YES |

### enterprise_inquiries
| column | type | nullable |
|--------|------|----------|
| id | text | NO |
| company_name | text | YES |
| name | text | YES |
| email | text | NO |
| use_case | text | YES |
| team_size | text | YES |
| features | ARRAY | YES |
| message | text | YES |
| created_at | timestamptz | YES |
| contacted | boolean | YES |

### enterprise_keys
| column | type | nullable |
|--------|------|----------|
| key_id | text | NO |
| account_id | text | YES |
| key_hint | text | YES |
| algorithm | text | YES |
| created_at | timestamptz | YES |
| rotated_at | timestamptz | YES |
| active | boolean | YES |

### event_hooks
| column | type | nullable |
|--------|------|----------|
| id | text | NO |
| agent_id | text | YES |
| url | text | NO |
| secret | text | YES |
| events | ARRAY | NO |
| enabled | boolean | YES |
| created_at | timestamptz | YES |
| last_fired | timestamptz | YES |
| failure_count | integer | YES |

### feature_flags
| column | type | nullable |
|--------|------|----------|
| key | text | NO |
| enabled | boolean | NO |
| updated_at | timestamptz | YES |
| updated_by | text | YES |

### hook_deliveries
| column | type | nullable |
|--------|------|----------|
| id | text | NO |
| hook_id | text | YES |
| event | text | NO |
| ctx_id | text | YES |
| status | text | YES |
| http_status | integer | YES |
| response | text | YES |
| duration_ms | integer | YES |
| attempted_at | timestamptz | YES |

### key_events
| column | type | nullable |
|--------|------|----------|
| id | bigint | NO |
| agent_id | text | NO |
| key_id | text | NO |
| event_type | text | NO |
| previous_key_id | text | YES |
| reason | text | YES |
| performed_by | text | YES |
| timestamp | timestamptz | YES |

### latest_checkpoint (view)
| column | type | nullable |
|--------|------|----------|
| checkpoint_id | text | YES |
| position | bigint | YES |
| tree_root | text | YES |
| tree_size | bigint | YES |
| log_root | text | YES |
| server_sig | text | YES |
| timestamp | timestamptz | YES |
| previous_cp_id | text | YES |
| previous_tree_root | text | YES |
| published | boolean | YES |
| published_url | text | YES |
| witness_count | integer | YES |
| witness_status | text | YES |

### log_entries
| column | type | nullable |
|--------|------|----------|
| position | bigint | NO |
| commit_id | text | NO |
| integrity_hash | text | NO |
| log_root | text | NO |
| server_sig | text | NO |
| timestamp | timestamptz | NO |
| created_at | timestamptz | YES |
| leaf_hash | text | YES |
| tree_root | text | YES |
| tree_size | bigint | YES |

### proxy_keys
| column | type | nullable |
|--------|------|----------|
| id | text | NO |
| workspace_id | text | NO |
| member_id | text | NO |
| proxy_key | text | NO |
| target_provider | text | NO |
| encrypted_real_key | text | YES |
| real_key_hint | text | YES |
| label | text | YES |
| is_active | boolean | NO |
| created_at | timestamptz | NO |
| last_used_at | timestamptz | YES |

### server_config
| column | type | nullable |
|--------|------|----------|
| key | text | NO |
| value | text | NO |
| set_at | timestamptz | YES |

### shared_chains
| column | type | nullable |
|--------|------|----------|
| id | text | NO |
| ctx_id | text | NO |
| created_by | text | YES |
| label | text | YES |
| expires_at | timestamptz | YES |
| view_count | integer | YES |
| created_at | timestamptz | YES |

### signing_keys
| column | type | nullable |
|--------|------|----------|
| id | uuid | NO |
| user_id | uuid | NO |
| key_id | text | NO |
| public_key | text | NO |
| algorithm | text | NO |
| status | text | NO |
| created_at | timestamptz | NO |
| revoked_at | timestamptz | YES |
| description | text | YES |

### spec_versions
| column | type | nullable |
|--------|------|----------|
| version | text | NO |
| published_at | timestamptz | YES |
| frozen_at | timestamptz | YES |
| changelog | text | YES |
| spec_url | text | YES |

### subscriptions
| column | type | nullable |
|--------|------|----------|
| id | text | NO |
| user_id | uuid | NO |
| stripe_customer_id | text | NO |
| plan | text | NO |
| status | text | NO |
| current_period_start | timestamptz | YES |
| current_period_end | timestamptz | YES |
| cancel_at_period_end | boolean | YES |
| stripe_price_id | text | YES |
| created_at | timestamptz | YES |
| updated_at | timestamptz | YES |

### user_recording_keys
| column | type | nullable |
|--------|------|----------|
| id | text | NO |
| user_id | uuid | YES |
| provider | text | NO |
| key_hint | text | NO |
| encrypted_key | text | YES |
| recording_enabled | boolean | YES |
| label | text | YES |
| created_at | timestamptz | YES |
| last_used_at | timestamptz | YES |

### webhook_deliveries
| column | type | nullable |
|--------|------|----------|
| id | text | NO |
| agent_id | text | YES |
| commit_id | text | YES |
| webhook_url | text | NO |
| status | text | NO |
| http_status | integer | YES |
| response | text | YES |
| attempted_at | timestamptz | YES |

### witness_sigs
| column | type | nullable |
|--------|------|----------|
| id | bigint | NO |
| checkpoint_id | text | NO |
| witness_id | text | NO |
| witness_sig | text | NO |
| witnessed_at | timestamptz | NO |
| sig_valid | boolean | YES |

### witnesses
| column | type | nullable |
|--------|------|----------|
| id | bigint | NO |
| witness_id | text | NO |
| name | text | NO |
| public_key_pem | text | NO |
| endpoint_url | text | YES |
| registered_at | timestamptz | YES |
| active | boolean | YES |
| deactivated_at | timestamptz | YES |
| deactivation_reason | text | YES |

### workspace_commits (view)
| column | type | nullable |
|--------|------|----------|
| id | text | YES |
| trace_id | text | YES |
| timestamp | timestamptz | YES |
| payload | jsonb | YES |
| integrity_hash | text | YES |
| payload_hash | text | YES |
| from_agent | text | YES |
| agent_info | jsonb | YES |
| event_type | text | YES |
| verified | boolean | YES |
| workspace_id | text | YES |
| member_email | text | YES |
| member_name | text | YES |
| member_role | text | YES |
| capture_source | text | YES |

### workspace_daily_stats
| column | type | nullable |
|--------|------|----------|
| workspace_id | text | NO |
| stat_date | date | NO |
| total_commits | integer | NO |
| ext_commits | integer | NO |
| proxy_commits | integer | NO |
| members_active | integer | NO |
| gaps_detected | integer | NO |

### workspace_invitations
| column | type | nullable |
|--------|------|----------|
| id | text | NO |
| workspace_id | text | NO |
| email | text | NO |
| role | text | NO |
| token | text | NO |
| invited_by | uuid | NO |
| accepted_at | timestamptz | YES |
| expires_at | timestamptz | NO |
| created_at | timestamptz | NO |

### workspace_members
| column | type | nullable |
|--------|------|----------|
| id | text | NO |
| workspace_id | text | NO |
| user_id | uuid | NO |
| email | text | NO |
| display_name | text | YES |
| role | text | NO |
| status | text | NO |
| agent_id | text | YES |
| joined_at | timestamptz | NO |
| last_active | timestamptz | YES |

### workspace_provider_keys
| column | type | nullable |
|--------|------|----------|
| id | uuid | NO |
| user_id | uuid | YES |
| provider | text | NO |
| encrypted_key | text | NO |
| key_hint | text | YES |
| recording_enabled | boolean | YES |
| label | text | YES |
| created_at | timestamptz | YES |
| last_used_at | timestamptz | YES |

### workspaces
| column | type | nullable |
|--------|------|----------|
| id | text | NO |
| name | text | NO |
| owner_user_id | uuid | NO |
| join_code | text | NO |
| plan | text | NO |
| policy_can_delete | boolean | NO |
| policy_capture_all | boolean | NO |
| policy_allowed_llms | ARRAY | NO |
| policy_export_permission | text | NO |
| policy_retention_days | integer | NO |
| proxy_enabled | boolean | NO |
| created_at | timestamptz | NO |
| updated_at | timestamptz | NO |
