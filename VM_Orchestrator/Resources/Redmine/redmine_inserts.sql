--
-- PostgreSQL database dump
--

-- Dumped from database version 13.0 (Debian 13.0-1.pgdg100+1)
-- Dumped by pg_dump version 13.0 (Debian 13.0-1.pgdg100+1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: ar_internal_metadata; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.ar_internal_metadata (
    key character varying NOT NULL,
    value character varying,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
);


ALTER TABLE public.ar_internal_metadata OWNER TO redmine;

--
-- Name: attachments; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.attachments (
    id integer NOT NULL,
    container_id integer,
    container_type character varying(30),
    filename character varying DEFAULT ''::character varying NOT NULL,
    disk_filename character varying DEFAULT ''::character varying NOT NULL,
    filesize bigint DEFAULT 0 NOT NULL,
    content_type character varying DEFAULT ''::character varying,
    digest character varying(64) DEFAULT ''::character varying NOT NULL,
    downloads integer DEFAULT 0 NOT NULL,
    author_id integer DEFAULT 0 NOT NULL,
    created_on timestamp without time zone,
    description character varying,
    disk_directory character varying
);


ALTER TABLE public.attachments OWNER TO redmine;

--
-- Name: attachments_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.attachments_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.attachments_id_seq OWNER TO redmine;

--
-- Name: attachments_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.attachments_id_seq OWNED BY public.attachments.id;


--
-- Name: auth_sources; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.auth_sources (
    id integer NOT NULL,
    type character varying(30) DEFAULT ''::character varying NOT NULL,
    name character varying(60) DEFAULT ''::character varying NOT NULL,
    host character varying(60),
    port integer,
    account character varying,
    account_password character varying DEFAULT ''::character varying,
    base_dn character varying(255),
    attr_login character varying(30),
    attr_firstname character varying(30),
    attr_lastname character varying(30),
    attr_mail character varying(30),
    onthefly_register boolean DEFAULT false NOT NULL,
    tls boolean DEFAULT false NOT NULL,
    filter text,
    timeout integer,
    verify_peer boolean DEFAULT true NOT NULL
);


ALTER TABLE public.auth_sources OWNER TO redmine;

--
-- Name: auth_sources_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.auth_sources_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.auth_sources_id_seq OWNER TO redmine;

--
-- Name: auth_sources_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.auth_sources_id_seq OWNED BY public.auth_sources.id;


--
-- Name: boards; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.boards (
    id integer NOT NULL,
    project_id integer NOT NULL,
    name character varying DEFAULT ''::character varying NOT NULL,
    description character varying,
    "position" integer,
    topics_count integer DEFAULT 0 NOT NULL,
    messages_count integer DEFAULT 0 NOT NULL,
    last_message_id integer,
    parent_id integer
);


ALTER TABLE public.boards OWNER TO redmine;

--
-- Name: boards_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.boards_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.boards_id_seq OWNER TO redmine;

--
-- Name: boards_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.boards_id_seq OWNED BY public.boards.id;


--
-- Name: changes; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.changes (
    id integer NOT NULL,
    changeset_id integer NOT NULL,
    action character varying(1) DEFAULT ''::character varying NOT NULL,
    path text NOT NULL,
    from_path text,
    from_revision character varying,
    revision character varying,
    branch character varying
);


ALTER TABLE public.changes OWNER TO redmine;

--
-- Name: changes_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.changes_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.changes_id_seq OWNER TO redmine;

--
-- Name: changes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.changes_id_seq OWNED BY public.changes.id;


--
-- Name: changeset_parents; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.changeset_parents (
    changeset_id integer NOT NULL,
    parent_id integer NOT NULL
);


ALTER TABLE public.changeset_parents OWNER TO redmine;

--
-- Name: changesets; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.changesets (
    id integer NOT NULL,
    repository_id integer NOT NULL,
    revision character varying NOT NULL,
    committer character varying,
    committed_on timestamp without time zone NOT NULL,
    comments text,
    commit_date date,
    scmid character varying,
    user_id integer
);


ALTER TABLE public.changesets OWNER TO redmine;

--
-- Name: changesets_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.changesets_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.changesets_id_seq OWNER TO redmine;

--
-- Name: changesets_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.changesets_id_seq OWNED BY public.changesets.id;


--
-- Name: changesets_issues; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.changesets_issues (
    changeset_id integer NOT NULL,
    issue_id integer NOT NULL
);


ALTER TABLE public.changesets_issues OWNER TO redmine;

--
-- Name: comments; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.comments (
    id integer NOT NULL,
    commented_type character varying(30) DEFAULT ''::character varying NOT NULL,
    commented_id integer DEFAULT 0 NOT NULL,
    author_id integer DEFAULT 0 NOT NULL,
    content text,
    created_on timestamp without time zone NOT NULL,
    updated_on timestamp without time zone NOT NULL
);


ALTER TABLE public.comments OWNER TO redmine;

--
-- Name: comments_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.comments_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.comments_id_seq OWNER TO redmine;

--
-- Name: comments_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.comments_id_seq OWNED BY public.comments.id;


--
-- Name: custom_field_enumerations; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.custom_field_enumerations (
    id integer NOT NULL,
    custom_field_id integer NOT NULL,
    name character varying NOT NULL,
    active boolean DEFAULT true NOT NULL,
    "position" integer DEFAULT 1 NOT NULL
);


ALTER TABLE public.custom_field_enumerations OWNER TO redmine;

--
-- Name: custom_field_enumerations_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.custom_field_enumerations_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.custom_field_enumerations_id_seq OWNER TO redmine;

--
-- Name: custom_field_enumerations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.custom_field_enumerations_id_seq OWNED BY public.custom_field_enumerations.id;


--
-- Name: custom_fields; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.custom_fields (
    id integer NOT NULL,
    type character varying(30) DEFAULT ''::character varying NOT NULL,
    name character varying(30) DEFAULT ''::character varying NOT NULL,
    field_format character varying(30) DEFAULT ''::character varying NOT NULL,
    possible_values text,
    regexp character varying DEFAULT ''::character varying,
    min_length integer,
    max_length integer,
    is_required boolean DEFAULT false NOT NULL,
    is_for_all boolean DEFAULT false NOT NULL,
    is_filter boolean DEFAULT false NOT NULL,
    "position" integer,
    searchable boolean DEFAULT false,
    default_value text,
    editable boolean DEFAULT true,
    visible boolean DEFAULT true NOT NULL,
    multiple boolean DEFAULT false,
    format_store text,
    description text
);


ALTER TABLE public.custom_fields OWNER TO redmine;

--
-- Name: custom_fields_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.custom_fields_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.custom_fields_id_seq OWNER TO redmine;

--
-- Name: custom_fields_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.custom_fields_id_seq OWNED BY public.custom_fields.id;


--
-- Name: custom_fields_projects; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.custom_fields_projects (
    custom_field_id integer DEFAULT 0 NOT NULL,
    project_id integer DEFAULT 0 NOT NULL
);


ALTER TABLE public.custom_fields_projects OWNER TO redmine;

--
-- Name: custom_fields_roles; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.custom_fields_roles (
    custom_field_id integer NOT NULL,
    role_id integer NOT NULL
);


ALTER TABLE public.custom_fields_roles OWNER TO redmine;

--
-- Name: custom_fields_trackers; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.custom_fields_trackers (
    custom_field_id integer DEFAULT 0 NOT NULL,
    tracker_id integer DEFAULT 0 NOT NULL
);


ALTER TABLE public.custom_fields_trackers OWNER TO redmine;

--
-- Name: custom_values; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.custom_values (
    id integer NOT NULL,
    customized_type character varying(30) DEFAULT ''::character varying NOT NULL,
    customized_id integer DEFAULT 0 NOT NULL,
    custom_field_id integer DEFAULT 0 NOT NULL,
    value text
);


ALTER TABLE public.custom_values OWNER TO redmine;

--
-- Name: custom_values_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.custom_values_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.custom_values_id_seq OWNER TO redmine;

--
-- Name: custom_values_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.custom_values_id_seq OWNED BY public.custom_values.id;


--
-- Name: documents; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.documents (
    id integer NOT NULL,
    project_id integer DEFAULT 0 NOT NULL,
    category_id integer DEFAULT 0 NOT NULL,
    title character varying DEFAULT ''::character varying NOT NULL,
    description text,
    created_on timestamp without time zone
);


ALTER TABLE public.documents OWNER TO redmine;

--
-- Name: documents_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.documents_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.documents_id_seq OWNER TO redmine;

--
-- Name: documents_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.documents_id_seq OWNED BY public.documents.id;


--
-- Name: email_addresses; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.email_addresses (
    id integer NOT NULL,
    user_id integer NOT NULL,
    address character varying NOT NULL,
    is_default boolean DEFAULT false NOT NULL,
    notify boolean DEFAULT true NOT NULL,
    created_on timestamp without time zone NOT NULL,
    updated_on timestamp without time zone NOT NULL
);


ALTER TABLE public.email_addresses OWNER TO redmine;

--
-- Name: email_addresses_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.email_addresses_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.email_addresses_id_seq OWNER TO redmine;

--
-- Name: email_addresses_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.email_addresses_id_seq OWNED BY public.email_addresses.id;


--
-- Name: enabled_modules; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.enabled_modules (
    id integer NOT NULL,
    project_id integer,
    name character varying NOT NULL
);


ALTER TABLE public.enabled_modules OWNER TO redmine;

--
-- Name: enabled_modules_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.enabled_modules_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.enabled_modules_id_seq OWNER TO redmine;

--
-- Name: enabled_modules_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.enabled_modules_id_seq OWNED BY public.enabled_modules.id;


--
-- Name: enumerations; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.enumerations (
    id integer NOT NULL,
    name character varying(30) DEFAULT ''::character varying NOT NULL,
    "position" integer,
    is_default boolean DEFAULT false NOT NULL,
    type character varying,
    active boolean DEFAULT true NOT NULL,
    project_id integer,
    parent_id integer,
    position_name character varying(30)
);


ALTER TABLE public.enumerations OWNER TO redmine;

--
-- Name: enumerations_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.enumerations_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.enumerations_id_seq OWNER TO redmine;

--
-- Name: enumerations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.enumerations_id_seq OWNED BY public.enumerations.id;


--
-- Name: groups_users; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.groups_users (
    group_id integer NOT NULL,
    user_id integer NOT NULL
);


ALTER TABLE public.groups_users OWNER TO redmine;

--
-- Name: import_items; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.import_items (
    id integer NOT NULL,
    import_id integer NOT NULL,
    "position" integer NOT NULL,
    obj_id integer,
    message text,
    unique_id character varying
);


ALTER TABLE public.import_items OWNER TO redmine;

--
-- Name: import_items_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.import_items_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.import_items_id_seq OWNER TO redmine;

--
-- Name: import_items_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.import_items_id_seq OWNED BY public.import_items.id;


--
-- Name: imports; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.imports (
    id integer NOT NULL,
    type character varying,
    user_id integer NOT NULL,
    filename character varying,
    settings text,
    total_items integer,
    finished boolean DEFAULT false NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
);


ALTER TABLE public.imports OWNER TO redmine;

--
-- Name: imports_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.imports_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.imports_id_seq OWNER TO redmine;

--
-- Name: imports_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.imports_id_seq OWNED BY public.imports.id;


--
-- Name: issue_categories; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.issue_categories (
    id integer NOT NULL,
    project_id integer DEFAULT 0 NOT NULL,
    name character varying(60) DEFAULT ''::character varying NOT NULL,
    assigned_to_id integer
);


ALTER TABLE public.issue_categories OWNER TO redmine;

--
-- Name: issue_categories_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.issue_categories_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.issue_categories_id_seq OWNER TO redmine;

--
-- Name: issue_categories_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.issue_categories_id_seq OWNED BY public.issue_categories.id;


--
-- Name: issue_relations; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.issue_relations (
    id integer NOT NULL,
    issue_from_id integer NOT NULL,
    issue_to_id integer NOT NULL,
    relation_type character varying DEFAULT ''::character varying NOT NULL,
    delay integer
);


ALTER TABLE public.issue_relations OWNER TO redmine;

--
-- Name: issue_relations_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.issue_relations_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.issue_relations_id_seq OWNER TO redmine;

--
-- Name: issue_relations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.issue_relations_id_seq OWNED BY public.issue_relations.id;


--
-- Name: issue_statuses; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.issue_statuses (
    id integer NOT NULL,
    name character varying(30) DEFAULT ''::character varying NOT NULL,
    is_closed boolean DEFAULT false NOT NULL,
    "position" integer,
    default_done_ratio integer
);


ALTER TABLE public.issue_statuses OWNER TO redmine;

--
-- Name: issue_statuses_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.issue_statuses_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.issue_statuses_id_seq OWNER TO redmine;

--
-- Name: issue_statuses_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.issue_statuses_id_seq OWNED BY public.issue_statuses.id;


--
-- Name: issues; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.issues (
    id integer NOT NULL,
    tracker_id integer NOT NULL,
    project_id integer NOT NULL,
    subject character varying DEFAULT ''::character varying NOT NULL,
    description text,
    due_date date,
    category_id integer,
    status_id integer NOT NULL,
    assigned_to_id integer,
    priority_id integer NOT NULL,
    fixed_version_id integer,
    author_id integer NOT NULL,
    lock_version integer DEFAULT 0 NOT NULL,
    created_on timestamp without time zone,
    updated_on timestamp without time zone,
    start_date date,
    done_ratio integer DEFAULT 0 NOT NULL,
    estimated_hours double precision,
    parent_id integer,
    root_id integer,
    lft integer,
    rgt integer,
    is_private boolean DEFAULT false NOT NULL,
    closed_on timestamp without time zone
);


ALTER TABLE public.issues OWNER TO redmine;

--
-- Name: issues_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.issues_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.issues_id_seq OWNER TO redmine;

--
-- Name: issues_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.issues_id_seq OWNED BY public.issues.id;


--
-- Name: journal_details; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.journal_details (
    id integer NOT NULL,
    journal_id integer DEFAULT 0 NOT NULL,
    property character varying(30) DEFAULT ''::character varying NOT NULL,
    prop_key character varying(30) DEFAULT ''::character varying NOT NULL,
    old_value text,
    value text
);


ALTER TABLE public.journal_details OWNER TO redmine;

--
-- Name: journal_details_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.journal_details_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.journal_details_id_seq OWNER TO redmine;

--
-- Name: journal_details_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.journal_details_id_seq OWNED BY public.journal_details.id;


--
-- Name: journals; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.journals (
    id integer NOT NULL,
    journalized_id integer DEFAULT 0 NOT NULL,
    journalized_type character varying(30) DEFAULT ''::character varying NOT NULL,
    user_id integer DEFAULT 0 NOT NULL,
    notes text,
    created_on timestamp without time zone NOT NULL,
    private_notes boolean DEFAULT false NOT NULL
);


ALTER TABLE public.journals OWNER TO redmine;

--
-- Name: journals_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.journals_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.journals_id_seq OWNER TO redmine;

--
-- Name: journals_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.journals_id_seq OWNED BY public.journals.id;


--
-- Name: member_roles; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.member_roles (
    id integer NOT NULL,
    member_id integer NOT NULL,
    role_id integer NOT NULL,
    inherited_from integer
);


ALTER TABLE public.member_roles OWNER TO redmine;

--
-- Name: member_roles_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.member_roles_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.member_roles_id_seq OWNER TO redmine;

--
-- Name: member_roles_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.member_roles_id_seq OWNED BY public.member_roles.id;


--
-- Name: members; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.members (
    id integer NOT NULL,
    user_id integer DEFAULT 0 NOT NULL,
    project_id integer DEFAULT 0 NOT NULL,
    created_on timestamp without time zone,
    mail_notification boolean DEFAULT false NOT NULL
);


ALTER TABLE public.members OWNER TO redmine;

--
-- Name: members_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.members_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.members_id_seq OWNER TO redmine;

--
-- Name: members_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.members_id_seq OWNED BY public.members.id;


--
-- Name: messages; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.messages (
    id integer NOT NULL,
    board_id integer NOT NULL,
    parent_id integer,
    subject character varying DEFAULT ''::character varying NOT NULL,
    content text,
    author_id integer,
    replies_count integer DEFAULT 0 NOT NULL,
    last_reply_id integer,
    created_on timestamp without time zone NOT NULL,
    updated_on timestamp without time zone NOT NULL,
    locked boolean DEFAULT false,
    sticky integer DEFAULT 0
);


ALTER TABLE public.messages OWNER TO redmine;

--
-- Name: messages_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.messages_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.messages_id_seq OWNER TO redmine;

--
-- Name: messages_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.messages_id_seq OWNED BY public.messages.id;


--
-- Name: news; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.news (
    id integer NOT NULL,
    project_id integer,
    title character varying(60) DEFAULT ''::character varying NOT NULL,
    summary character varying(255) DEFAULT ''::character varying,
    description text,
    author_id integer DEFAULT 0 NOT NULL,
    created_on timestamp without time zone,
    comments_count integer DEFAULT 0 NOT NULL
);


ALTER TABLE public.news OWNER TO redmine;

--
-- Name: news_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.news_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.news_id_seq OWNER TO redmine;

--
-- Name: news_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.news_id_seq OWNED BY public.news.id;


--
-- Name: open_id_authentication_associations; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.open_id_authentication_associations (
    id integer NOT NULL,
    issued integer,
    lifetime integer,
    handle character varying,
    assoc_type character varying,
    server_url bytea,
    secret bytea
);


ALTER TABLE public.open_id_authentication_associations OWNER TO redmine;

--
-- Name: open_id_authentication_associations_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.open_id_authentication_associations_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.open_id_authentication_associations_id_seq OWNER TO redmine;

--
-- Name: open_id_authentication_associations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.open_id_authentication_associations_id_seq OWNED BY public.open_id_authentication_associations.id;


--
-- Name: open_id_authentication_nonces; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.open_id_authentication_nonces (
    id integer NOT NULL,
    "timestamp" integer NOT NULL,
    server_url character varying,
    salt character varying NOT NULL
);


ALTER TABLE public.open_id_authentication_nonces OWNER TO redmine;

--
-- Name: open_id_authentication_nonces_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.open_id_authentication_nonces_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.open_id_authentication_nonces_id_seq OWNER TO redmine;

--
-- Name: open_id_authentication_nonces_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.open_id_authentication_nonces_id_seq OWNED BY public.open_id_authentication_nonces.id;


--
-- Name: projects; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.projects (
    id integer NOT NULL,
    name character varying DEFAULT ''::character varying NOT NULL,
    description text,
    homepage character varying DEFAULT ''::character varying,
    is_public boolean DEFAULT true NOT NULL,
    parent_id integer,
    created_on timestamp without time zone,
    updated_on timestamp without time zone,
    identifier character varying,
    status integer DEFAULT 1 NOT NULL,
    lft integer,
    rgt integer,
    inherit_members boolean DEFAULT false NOT NULL,
    default_version_id integer,
    default_assigned_to_id integer
);


ALTER TABLE public.projects OWNER TO redmine;

--
-- Name: projects_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.projects_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.projects_id_seq OWNER TO redmine;

--
-- Name: projects_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.projects_id_seq OWNED BY public.projects.id;


--
-- Name: projects_trackers; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.projects_trackers (
    project_id integer DEFAULT 0 NOT NULL,
    tracker_id integer DEFAULT 0 NOT NULL
);


ALTER TABLE public.projects_trackers OWNER TO redmine;

--
-- Name: queries; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.queries (
    id integer NOT NULL,
    project_id integer,
    name character varying DEFAULT ''::character varying NOT NULL,
    filters text,
    user_id integer DEFAULT 0 NOT NULL,
    column_names text,
    sort_criteria text,
    group_by character varying,
    type character varying,
    visibility integer DEFAULT 0,
    options text
);


ALTER TABLE public.queries OWNER TO redmine;

--
-- Name: queries_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.queries_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.queries_id_seq OWNER TO redmine;

--
-- Name: queries_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.queries_id_seq OWNED BY public.queries.id;


--
-- Name: queries_roles; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.queries_roles (
    query_id integer NOT NULL,
    role_id integer NOT NULL
);


ALTER TABLE public.queries_roles OWNER TO redmine;

--
-- Name: repositories; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.repositories (
    id integer NOT NULL,
    project_id integer DEFAULT 0 NOT NULL,
    url character varying DEFAULT ''::character varying NOT NULL,
    login character varying(60) DEFAULT ''::character varying,
    password character varying DEFAULT ''::character varying,
    root_url character varying(255) DEFAULT ''::character varying,
    type character varying,
    path_encoding character varying(64) DEFAULT NULL::character varying,
    log_encoding character varying(64) DEFAULT NULL::character varying,
    extra_info text,
    identifier character varying,
    is_default boolean DEFAULT false,
    created_on timestamp without time zone
);


ALTER TABLE public.repositories OWNER TO redmine;

--
-- Name: repositories_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.repositories_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.repositories_id_seq OWNER TO redmine;

--
-- Name: repositories_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.repositories_id_seq OWNED BY public.repositories.id;


--
-- Name: roles; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.roles (
    id integer NOT NULL,
    name character varying(255) DEFAULT ''::character varying NOT NULL,
    "position" integer,
    assignable boolean DEFAULT true,
    builtin integer DEFAULT 0 NOT NULL,
    permissions text,
    issues_visibility character varying(30) DEFAULT 'default'::character varying NOT NULL,
    users_visibility character varying(30) DEFAULT 'all'::character varying NOT NULL,
    time_entries_visibility character varying(30) DEFAULT 'all'::character varying NOT NULL,
    all_roles_managed boolean DEFAULT true NOT NULL,
    settings text
);


ALTER TABLE public.roles OWNER TO redmine;

--
-- Name: roles_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.roles_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.roles_id_seq OWNER TO redmine;

--
-- Name: roles_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.roles_id_seq OWNED BY public.roles.id;


--
-- Name: roles_managed_roles; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.roles_managed_roles (
    role_id integer NOT NULL,
    managed_role_id integer NOT NULL
);


ALTER TABLE public.roles_managed_roles OWNER TO redmine;

--
-- Name: schema_migrations; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.schema_migrations (
    version character varying NOT NULL
);


ALTER TABLE public.schema_migrations OWNER TO redmine;

--
-- Name: settings; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.settings (
    id integer NOT NULL,
    name character varying(255) DEFAULT ''::character varying NOT NULL,
    value text,
    updated_on timestamp without time zone
);


ALTER TABLE public.settings OWNER TO redmine;

--
-- Name: settings_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.settings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.settings_id_seq OWNER TO redmine;

--
-- Name: settings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.settings_id_seq OWNED BY public.settings.id;


--
-- Name: time_entries; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.time_entries (
    id integer NOT NULL,
    project_id integer NOT NULL,
    user_id integer NOT NULL,
    issue_id integer,
    hours double precision NOT NULL,
    comments character varying(1024),
    activity_id integer NOT NULL,
    spent_on date NOT NULL,
    tyear integer NOT NULL,
    tmonth integer NOT NULL,
    tweek integer NOT NULL,
    created_on timestamp without time zone NOT NULL,
    updated_on timestamp without time zone NOT NULL,
    author_id integer
);


ALTER TABLE public.time_entries OWNER TO redmine;

--
-- Name: time_entries_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.time_entries_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.time_entries_id_seq OWNER TO redmine;

--
-- Name: time_entries_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.time_entries_id_seq OWNED BY public.time_entries.id;


--
-- Name: tokens; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.tokens (
    id integer NOT NULL,
    user_id integer DEFAULT 0 NOT NULL,
    action character varying(30) DEFAULT ''::character varying NOT NULL,
    value character varying(40) DEFAULT ''::character varying NOT NULL,
    created_on timestamp without time zone NOT NULL,
    updated_on timestamp without time zone
);


ALTER TABLE public.tokens OWNER TO redmine;

--
-- Name: tokens_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.tokens_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.tokens_id_seq OWNER TO redmine;

--
-- Name: tokens_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.tokens_id_seq OWNED BY public.tokens.id;


--
-- Name: trackers; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.trackers (
    id integer NOT NULL,
    name character varying(30) DEFAULT ''::character varying NOT NULL,
    is_in_chlog boolean DEFAULT false NOT NULL,
    "position" integer,
    is_in_roadmap boolean DEFAULT true NOT NULL,
    fields_bits integer DEFAULT 0,
    default_status_id integer,
    description character varying
);


ALTER TABLE public.trackers OWNER TO redmine;

--
-- Name: trackers_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.trackers_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.trackers_id_seq OWNER TO redmine;

--
-- Name: trackers_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.trackers_id_seq OWNED BY public.trackers.id;


--
-- Name: user_preferences; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.user_preferences (
    id integer NOT NULL,
    user_id integer DEFAULT 0 NOT NULL,
    others text,
    hide_mail boolean DEFAULT true,
    time_zone character varying
);


ALTER TABLE public.user_preferences OWNER TO redmine;

--
-- Name: user_preferences_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.user_preferences_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.user_preferences_id_seq OWNER TO redmine;

--
-- Name: user_preferences_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.user_preferences_id_seq OWNED BY public.user_preferences.id;


--
-- Name: users; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.users (
    id integer NOT NULL,
    login character varying DEFAULT ''::character varying NOT NULL,
    hashed_password character varying(40) DEFAULT ''::character varying NOT NULL,
    firstname character varying(30) DEFAULT ''::character varying NOT NULL,
    lastname character varying(255) DEFAULT ''::character varying NOT NULL,
    admin boolean DEFAULT false NOT NULL,
    status integer DEFAULT 1 NOT NULL,
    last_login_on timestamp without time zone,
    language character varying(5) DEFAULT ''::character varying,
    auth_source_id integer,
    created_on timestamp without time zone,
    updated_on timestamp without time zone,
    type character varying,
    identity_url character varying,
    mail_notification character varying DEFAULT ''::character varying NOT NULL,
    salt character varying(64),
    must_change_passwd boolean DEFAULT false NOT NULL,
    passwd_changed_on timestamp without time zone
);


ALTER TABLE public.users OWNER TO redmine;

--
-- Name: users_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.users_id_seq OWNER TO redmine;

--
-- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;


--
-- Name: versions; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.versions (
    id integer NOT NULL,
    project_id integer DEFAULT 0 NOT NULL,
    name character varying DEFAULT ''::character varying NOT NULL,
    description character varying DEFAULT ''::character varying,
    effective_date date,
    created_on timestamp without time zone,
    updated_on timestamp without time zone,
    wiki_page_title character varying,
    status character varying DEFAULT 'open'::character varying,
    sharing character varying DEFAULT 'none'::character varying NOT NULL
);


ALTER TABLE public.versions OWNER TO redmine;

--
-- Name: versions_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.versions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.versions_id_seq OWNER TO redmine;

--
-- Name: versions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.versions_id_seq OWNED BY public.versions.id;


--
-- Name: watchers; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.watchers (
    id integer NOT NULL,
    watchable_type character varying DEFAULT ''::character varying NOT NULL,
    watchable_id integer DEFAULT 0 NOT NULL,
    user_id integer
);


ALTER TABLE public.watchers OWNER TO redmine;

--
-- Name: watchers_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.watchers_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.watchers_id_seq OWNER TO redmine;

--
-- Name: watchers_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.watchers_id_seq OWNED BY public.watchers.id;


--
-- Name: wiki_content_versions; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.wiki_content_versions (
    id integer NOT NULL,
    wiki_content_id integer NOT NULL,
    page_id integer NOT NULL,
    author_id integer,
    data bytea,
    compression character varying(6) DEFAULT ''::character varying,
    comments character varying(1024) DEFAULT ''::character varying,
    updated_on timestamp without time zone NOT NULL,
    version integer NOT NULL
);


ALTER TABLE public.wiki_content_versions OWNER TO redmine;

--
-- Name: wiki_content_versions_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.wiki_content_versions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.wiki_content_versions_id_seq OWNER TO redmine;

--
-- Name: wiki_content_versions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.wiki_content_versions_id_seq OWNED BY public.wiki_content_versions.id;


--
-- Name: wiki_contents; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.wiki_contents (
    id integer NOT NULL,
    page_id integer NOT NULL,
    author_id integer,
    text text,
    comments character varying(1024) DEFAULT ''::character varying,
    updated_on timestamp without time zone NOT NULL,
    version integer NOT NULL
);


ALTER TABLE public.wiki_contents OWNER TO redmine;

--
-- Name: wiki_contents_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.wiki_contents_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.wiki_contents_id_seq OWNER TO redmine;

--
-- Name: wiki_contents_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.wiki_contents_id_seq OWNED BY public.wiki_contents.id;


--
-- Name: wiki_pages; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.wiki_pages (
    id integer NOT NULL,
    wiki_id integer NOT NULL,
    title character varying(255) NOT NULL,
    created_on timestamp without time zone NOT NULL,
    protected boolean DEFAULT false NOT NULL,
    parent_id integer
);


ALTER TABLE public.wiki_pages OWNER TO redmine;

--
-- Name: wiki_pages_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.wiki_pages_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.wiki_pages_id_seq OWNER TO redmine;

--
-- Name: wiki_pages_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.wiki_pages_id_seq OWNED BY public.wiki_pages.id;


--
-- Name: wiki_redirects; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.wiki_redirects (
    id integer NOT NULL,
    wiki_id integer NOT NULL,
    title character varying,
    redirects_to character varying,
    created_on timestamp without time zone NOT NULL,
    redirects_to_wiki_id integer NOT NULL
);


ALTER TABLE public.wiki_redirects OWNER TO redmine;

--
-- Name: wiki_redirects_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.wiki_redirects_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.wiki_redirects_id_seq OWNER TO redmine;

--
-- Name: wiki_redirects_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.wiki_redirects_id_seq OWNED BY public.wiki_redirects.id;


--
-- Name: wikis; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.wikis (
    id integer NOT NULL,
    project_id integer NOT NULL,
    start_page character varying(255) NOT NULL,
    status integer DEFAULT 1 NOT NULL
);


ALTER TABLE public.wikis OWNER TO redmine;

--
-- Name: wikis_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.wikis_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.wikis_id_seq OWNER TO redmine;

--
-- Name: wikis_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.wikis_id_seq OWNED BY public.wikis.id;


--
-- Name: workflows; Type: TABLE; Schema: public; Owner: redmine
--

CREATE TABLE public.workflows (
    id integer NOT NULL,
    tracker_id integer DEFAULT 0 NOT NULL,
    old_status_id integer DEFAULT 0 NOT NULL,
    new_status_id integer DEFAULT 0 NOT NULL,
    role_id integer DEFAULT 0 NOT NULL,
    assignee boolean DEFAULT false NOT NULL,
    author boolean DEFAULT false NOT NULL,
    type character varying(30),
    field_name character varying(30),
    rule character varying(30)
);


ALTER TABLE public.workflows OWNER TO redmine;

--
-- Name: workflows_id_seq; Type: SEQUENCE; Schema: public; Owner: redmine
--

CREATE SEQUENCE public.workflows_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.workflows_id_seq OWNER TO redmine;

--
-- Name: workflows_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: redmine
--

ALTER SEQUENCE public.workflows_id_seq OWNED BY public.workflows.id;


--
-- Name: attachments id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.attachments ALTER COLUMN id SET DEFAULT nextval('public.attachments_id_seq'::regclass);


--
-- Name: auth_sources id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.auth_sources ALTER COLUMN id SET DEFAULT nextval('public.auth_sources_id_seq'::regclass);


--
-- Name: boards id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.boards ALTER COLUMN id SET DEFAULT nextval('public.boards_id_seq'::regclass);


--
-- Name: changes id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.changes ALTER COLUMN id SET DEFAULT nextval('public.changes_id_seq'::regclass);


--
-- Name: changesets id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.changesets ALTER COLUMN id SET DEFAULT nextval('public.changesets_id_seq'::regclass);


--
-- Name: comments id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.comments ALTER COLUMN id SET DEFAULT nextval('public.comments_id_seq'::regclass);


--
-- Name: custom_field_enumerations id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.custom_field_enumerations ALTER COLUMN id SET DEFAULT nextval('public.custom_field_enumerations_id_seq'::regclass);


--
-- Name: custom_fields id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.custom_fields ALTER COLUMN id SET DEFAULT nextval('public.custom_fields_id_seq'::regclass);


--
-- Name: custom_values id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.custom_values ALTER COLUMN id SET DEFAULT nextval('public.custom_values_id_seq'::regclass);


--
-- Name: documents id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.documents ALTER COLUMN id SET DEFAULT nextval('public.documents_id_seq'::regclass);


--
-- Name: email_addresses id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.email_addresses ALTER COLUMN id SET DEFAULT nextval('public.email_addresses_id_seq'::regclass);


--
-- Name: enabled_modules id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.enabled_modules ALTER COLUMN id SET DEFAULT nextval('public.enabled_modules_id_seq'::regclass);


--
-- Name: enumerations id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.enumerations ALTER COLUMN id SET DEFAULT nextval('public.enumerations_id_seq'::regclass);


--
-- Name: import_items id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.import_items ALTER COLUMN id SET DEFAULT nextval('public.import_items_id_seq'::regclass);


--
-- Name: imports id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.imports ALTER COLUMN id SET DEFAULT nextval('public.imports_id_seq'::regclass);


--
-- Name: issue_categories id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.issue_categories ALTER COLUMN id SET DEFAULT nextval('public.issue_categories_id_seq'::regclass);


--
-- Name: issue_relations id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.issue_relations ALTER COLUMN id SET DEFAULT nextval('public.issue_relations_id_seq'::regclass);


--
-- Name: issue_statuses id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.issue_statuses ALTER COLUMN id SET DEFAULT nextval('public.issue_statuses_id_seq'::regclass);


--
-- Name: issues id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.issues ALTER COLUMN id SET DEFAULT nextval('public.issues_id_seq'::regclass);


--
-- Name: journal_details id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.journal_details ALTER COLUMN id SET DEFAULT nextval('public.journal_details_id_seq'::regclass);


--
-- Name: journals id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.journals ALTER COLUMN id SET DEFAULT nextval('public.journals_id_seq'::regclass);


--
-- Name: member_roles id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.member_roles ALTER COLUMN id SET DEFAULT nextval('public.member_roles_id_seq'::regclass);


--
-- Name: members id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.members ALTER COLUMN id SET DEFAULT nextval('public.members_id_seq'::regclass);


--
-- Name: messages id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.messages ALTER COLUMN id SET DEFAULT nextval('public.messages_id_seq'::regclass);


--
-- Name: news id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.news ALTER COLUMN id SET DEFAULT nextval('public.news_id_seq'::regclass);


--
-- Name: open_id_authentication_associations id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.open_id_authentication_associations ALTER COLUMN id SET DEFAULT nextval('public.open_id_authentication_associations_id_seq'::regclass);


--
-- Name: open_id_authentication_nonces id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.open_id_authentication_nonces ALTER COLUMN id SET DEFAULT nextval('public.open_id_authentication_nonces_id_seq'::regclass);


--
-- Name: projects id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.projects ALTER COLUMN id SET DEFAULT nextval('public.projects_id_seq'::regclass);


--
-- Name: queries id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.queries ALTER COLUMN id SET DEFAULT nextval('public.queries_id_seq'::regclass);


--
-- Name: repositories id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.repositories ALTER COLUMN id SET DEFAULT nextval('public.repositories_id_seq'::regclass);


--
-- Name: roles id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.roles ALTER COLUMN id SET DEFAULT nextval('public.roles_id_seq'::regclass);


--
-- Name: settings id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.settings ALTER COLUMN id SET DEFAULT nextval('public.settings_id_seq'::regclass);


--
-- Name: time_entries id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.time_entries ALTER COLUMN id SET DEFAULT nextval('public.time_entries_id_seq'::regclass);


--
-- Name: tokens id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.tokens ALTER COLUMN id SET DEFAULT nextval('public.tokens_id_seq'::regclass);


--
-- Name: trackers id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.trackers ALTER COLUMN id SET DEFAULT nextval('public.trackers_id_seq'::regclass);


--
-- Name: user_preferences id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.user_preferences ALTER COLUMN id SET DEFAULT nextval('public.user_preferences_id_seq'::regclass);


--
-- Name: users id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);


--
-- Name: versions id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.versions ALTER COLUMN id SET DEFAULT nextval('public.versions_id_seq'::regclass);


--
-- Name: watchers id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.watchers ALTER COLUMN id SET DEFAULT nextval('public.watchers_id_seq'::regclass);


--
-- Name: wiki_content_versions id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.wiki_content_versions ALTER COLUMN id SET DEFAULT nextval('public.wiki_content_versions_id_seq'::regclass);


--
-- Name: wiki_contents id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.wiki_contents ALTER COLUMN id SET DEFAULT nextval('public.wiki_contents_id_seq'::regclass);


--
-- Name: wiki_pages id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.wiki_pages ALTER COLUMN id SET DEFAULT nextval('public.wiki_pages_id_seq'::regclass);


--
-- Name: wiki_redirects id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.wiki_redirects ALTER COLUMN id SET DEFAULT nextval('public.wiki_redirects_id_seq'::regclass);


--
-- Name: wikis id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.wikis ALTER COLUMN id SET DEFAULT nextval('public.wikis_id_seq'::regclass);


--
-- Name: workflows id; Type: DEFAULT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.workflows ALTER COLUMN id SET DEFAULT nextval('public.workflows_id_seq'::regclass);


--
-- Data for Name: ar_internal_metadata; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.ar_internal_metadata (key, value, created_at, updated_at) FROM stdin;
environment	production	2020-09-04 16:38:13.53414	2020-09-04 16:38:13.53414
\.


--
-- Data for Name: attachments; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.attachments (id, container_id, container_type, filename, disk_filename, filesize, content_type, digest, downloads, author_id, created_on, description, disk_directory) FROM stdin;
\.


--
-- Data for Name: auth_sources; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.auth_sources (id, type, name, host, port, account, account_password, base_dn, attr_login, attr_firstname, attr_lastname, attr_mail, onthefly_register, tls, filter, timeout, verify_peer) FROM stdin;
\.


--
-- Data for Name: boards; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.boards (id, project_id, name, description, "position", topics_count, messages_count, last_message_id, parent_id) FROM stdin;
\.


--
-- Data for Name: changes; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.changes (id, changeset_id, action, path, from_path, from_revision, revision, branch) FROM stdin;
\.


--
-- Data for Name: changeset_parents; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.changeset_parents (changeset_id, parent_id) FROM stdin;
\.


--
-- Data for Name: changesets; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.changesets (id, repository_id, revision, committer, committed_on, comments, commit_date, scmid, user_id) FROM stdin;
\.


--
-- Data for Name: changesets_issues; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.changesets_issues (changeset_id, issue_id) FROM stdin;
\.


--
-- Data for Name: comments; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.comments (id, commented_type, commented_id, author_id, content, created_on, updated_on) FROM stdin;
\.


--
-- Data for Name: custom_field_enumerations; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.custom_field_enumerations (id, custom_field_id, name, active, "position") FROM stdin;
\.


--
-- Data for Name: custom_fields; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.custom_fields (id, type, name, field_format, possible_values, regexp, min_length, max_length, is_required, is_for_all, is_filter, "position", searchable, default_value, editable, visible, multiple, format_store, description) FROM stdin;
2	IssueCustomField	Identifier	string	\N		\N	\N	t	t	f	1	f		t	t	f	--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: ''\nurl_pattern: ''\n	Mongo Identifier
3	IssueCustomField	Domain	string	\N		\N	\N	t	t	t	2	f		t	t	f	--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: ''\nurl_pattern: ''\n	
4	IssueCustomField	Resource	string	\N		\N	\N	t	t	t	3	f		t	t	f	--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: ''\nurl_pattern: ''\n	
5	IssueCustomField	Date Found	date	\N		\N	\N	t	t	f	4	f		t	t	f	--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\nurl_pattern: ''\n	
6	IssueCustomField	Last Seen	date	\N		\N	\N	t	t	f	5	f		t	t	f	--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\nurl_pattern: ''\n	
7	IssueCustomField	CVSS Score	string	\N		\N	\N	t	t	f	6	f		t	t	f	--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: ''\nurl_pattern: ''\n	
8	IssueCustomField	KB Description	string	\N		\N	\N	f	t	f	7	f		t	t	f	--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: ''\nurl_pattern: ''\n	
9	IssueCustomField	KB Description Notes	string	\N		\N	\N	f	t	f	8	f		t	t	f	--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: ''\nurl_pattern: ''\n	
10	IssueCustomField	KB Implication	string	\N		\N	\N	f	t	f	9	f		t	t	f	--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: ''\nurl_pattern: ''\n	
11	IssueCustomField	KB Recommendation	string	\N		\N	\N	f	t	f	10	f		t	t	f	--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: ''\nurl_pattern: ''\n	
12	IssueCustomField	KB Recommendation Notes	string	\N		\N	\N	f	t	f	11	f		t	t	f	--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: ''\nurl_pattern: ''\n	
13	IssueCustomField	Component	string	\N		\N	\N	t	t	f	12	f		t	t	f	--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: ''\nurl_pattern: ''\n	
14	IssueCustomField	Line	string	\N		\N	\N	t	t	f	13	f		t	t	f	--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: ''\nurl_pattern: ''\n	
16	IssueCustomField	First Commit	string	\N		\N	\N	t	t	f	15	f		t	t	f	--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: ''\nurl_pattern: ''\n	
17	IssueCustomField	Last Commit	string	\N		\N	\N	t	t	f	16	f		t	t	f	--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: ''\nurl_pattern: ''\n	
18	IssueCustomField	Username	string	\N		\N	\N	t	t	f	17	f		t	t	f	--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: ''\nurl_pattern: ''\n	
20	IssueCustomField	Tool Severity	string	\N		\N	\N	t	t	t	19	f		t	t	f	--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: ''\nurl_pattern: ''\n	
15	IssueCustomField	Affected Code	string	\N		\N	\N	t	t	f	14	f		t	t	f	--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: ''\nurl_pattern: ''\n	
19	IssueCustomField	Pipeline Name	string	\N		\N	\N	t	t	f	18	f		t	t	f	--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: ''\nurl_pattern: ''\n	
21	IssueCustomField	branch	string	\N		\N	\N	t	t	f	20	f		t	t	f	--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: ''\nurl_pattern: ''\n	
\.


--
-- Data for Name: custom_fields_projects; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.custom_fields_projects (custom_field_id, project_id) FROM stdin;
\.


--
-- Data for Name: custom_fields_roles; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.custom_fields_roles (custom_field_id, role_id) FROM stdin;
\.


--
-- Data for Name: custom_fields_trackers; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.custom_fields_trackers (custom_field_id, tracker_id) FROM stdin;
2	4
2	5
2	6
3	4
3	5
4	4
4	5
5	4
5	5
5	6
6	4
6	5
6	6
7	4
7	5
7	6
8	4
8	5
8	6
9	4
9	5
9	6
10	4
10	5
10	6
11	4
11	5
11	6
12	4
12	5
12	6
13	6
14	6
15	6
16	6
17	6
18	6
19	6
20	6
21	6
\.


--
-- Data for Name: custom_values; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.custom_values (id, customized_type, customized_id, custom_field_id, value) FROM stdin;
115	Issue	2	8	
118	Issue	2	9	
120	Issue	3	8	
122	Issue	1	8	
123	Issue	2	10	
124	Issue	1	9	
125	Issue	3	9	
126	Issue	2	11	
127	Issue	4	8	
128	Issue	3	10	
129	Issue	4	9	
130	Issue	1	10	
131	Issue	4	10	
132	Issue	2	12	
133	Issue	1	11	
134	Issue	3	11	
135	Issue	1	12	
136	Issue	4	11	
138	Issue	3	12	
139	Issue	4	12	
105	Issue	1	2	5faeaa7ce26515be1c4232fd
107	Issue	1	5	2020-11-13
110	Issue	4	2	5faeaa7bb230fdf62c4232fd
103	Issue	3	2	5faeaa7cadf61d84d74232fd
114	Issue	1	6	2020-11-13
108	Issue	3	5	2020-11-13
111	Issue	4	5	2020-11-13
119	Issue	1	7	0
113	Issue	3	6	2020-11-13
117	Issue	4	6	2020-11-13
116	Issue	3	7	0
140	Issue	1	13	chromecast/src/interceptors.js
104	Issue	2	2	5faeaa7cbe305cbbde4232fd
144	Issue	3	13	src/state/detailsOverlay/sagas.js
121	Issue	4	7	0
106	Issue	2	5	2020-11-13
143	Issue	4	13	chromecast/src/components/api.js
149	Issue	3	14	25
142	Issue	1	14	96
109	Issue	2	6	2020-11-13
148	Issue	4	14	90
152	Issue	3	15	  try {     const { resourceType = '', blimAsset = false, id = '' } = infoCard;     let populatedInfoCard = infoCard;      if (!blimAsset && resourceType !== RESOURCE_TYPES_ORBIS.SHOWS) {       const { description = '' } = infoCard;        if (!description) {         const { data: entity = {} } = yield call(getEntityService, id);         populatedInfoCard = { ...populatedInfoCard, ...entity};       }     }      if (RESOURCES_BY_TYPE.epg.some(epgResource => resourceType === epgResource)) {       const { stationID = '', stationName = '' } = populatedInfoCard;        if (!stationName && stationID) {         populatedInfoCard = yield call(populateWithStationName, populatedInfoCard);       }     }      if (blimAsset && resourceType === RESOURCE_TYPE_BLIM.MOVIE) {       const { data } = yield call(getBlimMovieDetailsService, id);       const parseAsset = getOrbisAssetsFromBlim([data])[0] || {};       populatedInfoCard = { ...populatedInfoCard, ...parseAsset, resourceType: RESOURCE_TYPE_BLIM.MOVIE };     }      yield put(showDetailsOverlayWithData(populatedInfoCard));   } catch (error) {     console.error(`detailsOverlaySaga-populateInfoCard: ${error}`);   }
112	Issue	2	7	0
145	Issue	1	15	      try {         const newSessionToken = await getToken(sessionToken);         !url.includes(API.BLIM_EXPERIENCE_BASE_PATH) && setL(config, 'headers.Authorization', `Bearer ${newSessionToken}`);       } catch (error) {         console.error(error);       };
156	Issue	3	16	2933fd9
151	Issue	4	15	  try {     const masterAsset = await getAssetInfo(contentId);     const manifest = masterAsset.data;     const parser = new DOMParser();     let parsedManifest = parser.parseFromString(manifest, 'text/xml');     let psshElements = parsedManifest.querySelectorAll(       'ContentProtection[schemeIdUri="urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed"] > pssh'     );     if (psshElements && psshElements.length > 0) {       let stringToDecode = psshElements[0].innerHTML || psshElements[0].textContent;       let psshDecoded = atob(stringToDecode);       let encodedCompanyCode = psshDecoded.match(/istreamplanet"(.*)/)[1];       [companyId] = atob(encodedCompanyCode).split(';');     } else {       console.error(         'PSSH Element not detected in manifest. Default companyID to be used: ',         process.env.REACT_APP_DRM_COMPANY_ID       );     }    } catch (error) {     console.error(error.toString(), process.env.REACT_APP_DRM_COMPANY_ID);   }
147	Issue	1	16	2933fd9
159	Issue	3	17	2933fd9
137	Issue	2	13	chromecast/src/utils/actionsGlobal.js
154	Issue	4	16	2933fd9
150	Issue	1	17	2933fd9
141	Issue	2	14	260
173	Issue	3	21	develop
169	Issue	4	21	develop
158	Issue	2	17	2933fd9
163	Issue	2	18	johndaniel.castro@globant.com
167	Issue	2	19	dtvweb
171	Issue	2	20	Low
174	Issue	2	21	develop
157	Issue	4	17	2933fd9
161	Issue	4	18	johndaniel.castro@globant.com
164	Issue	4	19	dtvweb
166	Issue	4	20	Low
179	Issue	5	8	
180	Issue	5	9	
181	Issue	5	10	
182	Issue	5	11	
183	Issue	5	12	
175	Issue	5	2	5faeaa7de26515be1c4232ff
176	Issue	5	5	2020-11-13
177	Issue	5	6	2020-11-13
178	Issue	5	7	0
184	Issue	5	13	src/state/home/homeTab/sagas.js
185	Issue	5	14	97
186	Issue	5	15	  try {     const group = [];     const firstIndex = (lastPageCalled - 1) * PAGE_SIZE, lastIndex = lastPageCalled * PAGE_SIZE;     const sectionsGroup = allSectionsToLoad.slice(firstIndex, lastIndex);     const groupIds = sectionsGroup.map(({ id }) => id);     const sectionsData = yield getSections(groupIds, LANDERS_URIS.HOME);     const updatedSections = allSectionsToLoad.map((section) => {       const { id } = section;       const { assets, name, key } = sectionsData[id] ? sectionsData[id] : {};        if (!!sectionsData[id]) {         return {           id,           key,           assets,           name,           requested: true         };       }        return section;     });      for (const indexSection in sectionsGroup) {       const absoluteIndexSection = Number(indexSection) + firstIndex;        if (updatedSections[absoluteIndexSection].requested) {         const section = updatedSections[absoluteIndexSection];          if (section !== null) {           const { id, key, assets } = section;            if (assets && (assets.length || id === SECTIONS_URIS.MY_LIST)) {             if (key === MY_LIST_SLIDER_KEY) {               yield put(getMyListSuccess(assets));             }              updatedSections[absoluteIndexSection].assets = yield call(populateFeaturedWithStationName, assets);             group.push(updatedSections[absoluteIndexSection]);           }         }       }     }      return {       group,       updatedSections,       keepRequesting: (lastIndex < allSectionsToLoad.length)     };    } catch (error) {     console.error(`homeTabSaga-homeTab: ${error}`);   }
187	Issue	5	16	2933fd9
188	Issue	5	17	2933fd9
189	Issue	5	18	johndaniel.castro@globant.com
190	Issue	5	19	dtvweb
192	Issue	5	20	Low
195	Issue	5	21	develop
251	Issue	9	8	
252	Issue	9	9	
253	Issue	9	10	
254	Issue	9	11	
255	Issue	9	12	
247	Issue	9	2	5faeaa7ee26515be1c423301
248	Issue	9	5	2020-11-13
249	Issue	9	6	2020-11-13
250	Issue	9	7	0
256	Issue	9	13	src/utils/actionsGlobal.js
257	Issue	9	14	994
258	Issue	9	15	  try {     if (url.indexOf("//") > -1) {       hostname = url.split('/')[2];     } else {       hostname = url.split('/')[0];     }     //find & remove port number     hostname = hostname.split(':')[0];     //find & remove "?"     hostname = hostname.split('?')[0];   } catch (e) {     console.error(e);   }
259	Issue	9	16	2933fd9
260	Issue	9	17	2933fd9
261	Issue	9	18	johndaniel.castro@globant.com
263	Issue	9	19	dtvweb
264	Issue	9	20	Low
266	Issue	9	21	develop
363	Issue	16	8	
365	Issue	16	9	
367	Issue	16	10	
368	Issue	16	11	
369	Issue	16	12	
356	Issue	16	2	5faeaa80adf61d84d7423303
358	Issue	16	5	2020-11-13
360	Issue	16	6	2020-11-13
362	Issue	16	7	0
371	Issue	16	13	src/utils/actionsGlobal.js
373	Issue	16	14	1345
375	Issue	16	15	  return (+new Date() + Math.random() * 100).toString(32);
377	Issue	16	16	2933fd9
378	Issue	16	17	2933fd9
381	Issue	16	18	johndaniel.castro@globant.com
384	Issue	16	19	dtvweb
386	Issue	16	20	Low
388	Issue	16	21	develop
155	Issue	1	18	johndaniel.castro@globant.com
160	Issue	1	19	dtvweb
162	Issue	1	20	Low
170	Issue	1	21	develop
212	Issue	8	8	
215	Issue	8	9	
219	Issue	8	10	
222	Issue	8	11	
224	Issue	8	12	
199	Issue	8	2	5faeaa7dadf61d84d74232ff
202	Issue	8	5	2020-11-13
203	Issue	8	6	2020-11-13
209	Issue	8	7	0
227	Issue	8	13	src/state/sections/sagas.js
230	Issue	8	14	30
233	Issue	8	15	  try {     const timeZone = getTimeZone();     const { account: { entitlements = [] } = {} } = user;     const entitlementsString = entitlements       .map(({ package: { id = '' } = {} }) => id)       .join(', ');      const {       data: { section: { items = [], label = '' } = {} } = {}     } = yield call(getContinueWatchingService, timeZone, entitlementsString);      return {       data: {         section: {           label,           sectionID: sectionId,           subsections: [{             items,             blockLabel: label,             subsectionName: CONTINUE_WATCHING_SLIDER_KEY           }]         }       }     };   } catch (error) {     console.error(`sections>saga-getContinueWatching: ${error}`);   }
234	Issue	8	16	2933fd9
236	Issue	8	17	2933fd9
238	Issue	8	18	johndaniel.castro@globant.com
240	Issue	8	19	dtvweb
242	Issue	8	20	Low
244	Issue	8	21	develop
269	Issue	10	8	
270	Issue	10	9	
271	Issue	10	10	
272	Issue	10	11	
273	Issue	10	12	
262	Issue	10	2	5faeaa7eb230fdf62c423301
265	Issue	10	5	2020-11-13
267	Issue	10	6	2020-11-13
268	Issue	10	7	0
274	Issue	10	13	src/utils/actionsGlobal.js
275	Issue	10	14	1320
276	Issue	10	15	  try {     await eventReportGA(gaParams);   } catch (error) {     console.error(`actionsGlobal-gaReportError: ${error}`);   }
277	Issue	10	16	2933fd9
278	Issue	10	17	2933fd9
279	Issue	10	18	johndaniel.castro@globant.com
281	Issue	10	19	dtvweb
284	Issue	10	20	Low
285	Issue	10	21	develop
364	Issue	15	8	
366	Issue	15	9	
370	Issue	15	10	
372	Issue	15	11	
374	Issue	15	12	
355	Issue	15	2	5faeaa80be305cbbde423303
357	Issue	15	5	2020-11-13
359	Issue	15	6	2020-11-13
361	Issue	15	7	0
376	Issue	15	13	src/userMenu/settings/general/GeneralContainer.js
379	Issue	15	14	15
380	Issue	15	15	export const CHANGE_PASSWORD = 'CHANGE_PASSWORD';
382	Issue	15	16	2933fd9
383	Issue	15	17	2933fd9
385	Issue	15	18	johndaniel.castro@globant.com
387	Issue	15	19	dtvweb
389	Issue	15	20	Medium
390	Issue	15	21	develop
431	Issue	19	8	
432	Issue	19	9	
433	Issue	19	10	
434	Issue	19	11	
435	Issue	19	12	
427	Issue	19	2	5faeaa82adf61d84d7423305
428	Issue	19	5	2020-11-13
429	Issue	19	6	2020-11-13
430	Issue	19	7	0
436	Issue	19	13	src/utils/localStorageState.js
437	Issue	19	14	66
438	Issue	19	15	    sessionToken && localStorage.setItem(SESSION_TOKEN, sessionToken);
439	Issue	19	16	2933fd9
440	Issue	19	17	2933fd9
441	Issue	19	18	johndaniel.castro@globant.com
442	Issue	19	19	dtvweb
443	Issue	19	20	LOW
444	Issue	19	21	develop
165	Issue	3	18	johndaniel.castro@globant.com
168	Issue	3	19	dtvweb
172	Issue	3	20	Low
198	Issue	6	8	
200	Issue	6	9	
204	Issue	6	10	
205	Issue	6	11	
207	Issue	6	12	
191	Issue	6	2	5faeaa7db230fdf62c4232ff
193	Issue	6	5	2020-11-13
194	Issue	6	6	2020-11-13
196	Issue	6	7	0
211	Issue	6	13	src/state/search/sagas.js
213	Issue	6	14	72
214	Issue	6	15	  try {     if (query.length < SEARCH_KEYWORD_THRESHOLD) {       yield put(replace({ search: null }));       return yield call(cleanSearch);     }      yield put(replace({ search: qs.stringify({ q: query }, { format: 'RFC1738' }) }));     yield put(actions.search(query));   } catch (error) {     console.error(`searchSaga-updateSearchTerm: ${error}`);   }
218	Issue	6	16	2933fd9
220	Issue	6	17	2933fd9
223	Issue	6	18	johndaniel.castro@globant.com
226	Issue	6	19	dtvweb
228	Issue	6	20	Low
232	Issue	6	21	develop
289	Issue	11	8	
292	Issue	11	9	
294	Issue	11	10	
295	Issue	11	11	
296	Issue	11	12	
280	Issue	11	2	5faeaa7eadf61d84d7423301
282	Issue	11	5	2020-11-13
283	Issue	11	6	2020-11-13
286	Issue	11	7	0
299	Issue	11	13	src/utils/localStorageState.js
300	Issue	11	14	77
302	Issue	11	15	  try {     const {       digitalData: {         user: { numberOfVisitsEver, numberOfVisitsMonth, lastVisits }, session: { dayLastSession }       } } = global;     localStorage.clear();     let serializedDataLayer = {       user: { numberOfVisitsEver, numberOfVisitsMonth, lastVisits }, session: { dayLastSession }     };     serializedDataLayer = JSON.stringify(serializedDataLayer);     localStorage.setItem(DATA_LAYER, serializedDataLayer);   } catch (error) {     console.error(`localStorageState-clearState: ${error}`);   }
304	Issue	11	16	2933fd9
305	Issue	11	17	2933fd9
308	Issue	11	18	johndaniel.castro@globant.com
310	Issue	11	19	dtvweb
311	Issue	11	20	Low
314	Issue	11	21	develop
323	Issue	13	8	
324	Issue	13	9	
325	Issue	13	10	
326	Issue	13	11	
327	Issue	13	12	
319	Issue	13	2	5faeaa7fe26515be1c423303
320	Issue	13	5	2020-11-13
321	Issue	13	6	2020-11-13
322	Issue	13	7	0
328	Issue	13	13	chromecast/src/utils/actionsGlobal.js
331	Issue	13	14	187
334	Issue	13	15	  return (+new Date() + Math.random() * 100).toString(32);
336	Issue	13	16	2933fd9
338	Issue	13	17	2933fd9
340	Issue	13	18	johndaniel.castro@globant.com
342	Issue	13	19	dtvweb
345	Issue	13	20	Low
348	Issue	13	21	develop
146	Issue	2	15	  try {     if (url.indexOf("//") > -1) {       hostname = url.split('/')[2];     } else {       hostname = url.split('/')[0];     }     //find & remove port number     hostname = hostname.split(':')[0];     //find & remove "?"     hostname = hostname.split('?')[0];   } catch (e) {     console.error(e);   }
153	Issue	2	16	2933fd9
210	Issue	7	8	
216	Issue	7	9	
217	Issue	7	10	
221	Issue	7	11	
225	Issue	7	12	
197	Issue	7	2	5faeaa7dbe305cbbde4232ff
201	Issue	7	5	2020-11-13
206	Issue	7	6	2020-11-13
208	Issue	7	7	0
229	Issue	7	13	src/state/search/sagas.js
231	Issue	7	14	163
235	Issue	7	15	  try {     yield put(actions.searchReset());   } catch (error) {     console.error(`searchSaga-cleanSearch: ${error}`);   }
237	Issue	7	16	2933fd9
239	Issue	7	17	2933fd9
241	Issue	7	18	johndaniel.castro@globant.com
243	Issue	7	19	dtvweb
245	Issue	7	20	Low
246	Issue	7	21	develop
293	Issue	12	8	
297	Issue	12	9	
298	Issue	12	10	
301	Issue	12	11	
303	Issue	12	12	
287	Issue	12	2	5faeaa7ebe305cbbde423301
288	Issue	12	5	2020-11-13
290	Issue	12	6	2020-11-13
291	Issue	12	7	0
306	Issue	12	13	chromecast/src/components/chromecastContainer/ChromecastContainer.js
307	Issue	12	14	36
309	Issue	12	15	    const deviceId = (+new Date() + Math.random() * 100).toString(32);
312	Issue	12	16	2933fd9
313	Issue	12	17	2933fd9
315	Issue	12	18	johndaniel.castro@globant.com
316	Issue	12	19	dtvweb
317	Issue	12	20	Low
318	Issue	12	21	develop
335	Issue	14	8	
337	Issue	14	9	
339	Issue	14	10	
341	Issue	14	11	
343	Issue	14	12	
329	Issue	14	2	5faeaa7fb230fdf62c423303
330	Issue	14	5	2020-11-13
332	Issue	14	6	2020-11-13
333	Issue	14	7	0
344	Issue	14	13	src/dataLayer/entities/User.js
346	Issue	14	14	19
347	Issue	14	15	        defaultValue: `000-${+new Date()}-${(Math.random() * 100).toString(32)}`
349	Issue	14	16	2933fd9
350	Issue	14	17	2933fd9
351	Issue	14	18	johndaniel.castro@globant.com
352	Issue	14	19	dtvweb
353	Issue	14	20	Low
354	Issue	14	21	develop
395	Issue	17	8	
396	Issue	17	9	
397	Issue	17	10	
398	Issue	17	11	
399	Issue	17	12	
411	Issue	18	8	
414	Issue	18	9	
415	Issue	18	10	
416	Issue	18	11	
391	Issue	17	2	5faeaa82e26515be1c423305
417	Issue	18	12	
392	Issue	17	5	2020-11-13
393	Issue	17	6	2020-11-13
394	Issue	17	7	0
400	Issue	17	13	src/state/ads/actionTypes.js
401	Issue	17	14	19
402	Issue	17	15	export const USER_CONFIG = 'ads/USER_CONFIG';
404	Issue	17	16	2933fd9
406	Issue	17	17	2933fd9
408	Issue	17	18	johndaniel.castro@globant.com
410	Issue	17	19	dtvweb
412	Issue	17	20	Medium
413	Issue	17	21	develop
403	Issue	18	2	5faeaa82b230fdf62c423305
405	Issue	18	5	2020-11-13
407	Issue	18	6	2020-11-13
409	Issue	18	7	0
418	Issue	18	13	src/utils/localStorageState.js
419	Issue	18	14	20
420	Issue	18	15	const USER = 'user';
421	Issue	18	16	2933fd9
422	Issue	18	17	2933fd9
423	Issue	18	18	johndaniel.castro@globant.com
424	Issue	18	19	dtvweb
425	Issue	18	20	Medium
426	Issue	18	21	develop
\.


--
-- Data for Name: documents; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.documents (id, project_id, category_id, title, description, created_on) FROM stdin;
\.


--
-- Data for Name: email_addresses; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.email_addresses (id, user_id, address, is_default, notify, created_on, updated_on) FROM stdin;
1	1	admin@example.net	t	t	2020-09-04 16:38:12.766845	2020-09-04 16:38:12.766845
\.


--
-- Data for Name: enabled_modules; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.enabled_modules (id, project_id, name) FROM stdin;
11	1	issue_tracking
12	1	time_tracking
13	1	news
14	1	documents
15	1	files
16	1	wiki
17	1	repository
18	1	boards
19	1	calendar
20	1	gantt
\.


--
-- Data for Name: enumerations; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.enumerations (id, name, "position", is_default, type, active, project_id, parent_id, position_name) FROM stdin;
6	User documentation	1	f	DocumentCategory	t	\N	\N	\N
7	Technical documentation	2	f	DocumentCategory	t	\N	\N	\N
8	Design	1	f	TimeEntryActivity	t	\N	\N	\N
9	Development	2	f	TimeEntryActivity	t	\N	\N	\N
10	Informational	1	f	IssuePriority	t	\N	\N	lowest
1	Low	2	f	IssuePriority	t	\N	\N	low2
11	Medium	3	f	IssuePriority	t	\N	\N	default
3	High	4	f	IssuePriority	t	\N	\N	high2
12	Critical	5	f	IssuePriority	t	\N	\N	highest
\.


--
-- Data for Name: groups_users; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.groups_users (group_id, user_id) FROM stdin;
\.


--
-- Data for Name: import_items; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.import_items (id, import_id, "position", obj_id, message, unique_id) FROM stdin;
\.


--
-- Data for Name: imports; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.imports (id, type, user_id, filename, settings, total_items, finished, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: issue_categories; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.issue_categories (id, project_id, name, assigned_to_id) FROM stdin;
\.


--
-- Data for Name: issue_relations; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.issue_relations (id, issue_from_id, issue_to_id, relation_type, delay) FROM stdin;
\.


--
-- Data for Name: issue_statuses; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.issue_statuses (id, name, is_closed, "position", default_done_ratio) FROM stdin;
1	New	f	1	\N
2	In Progress	f	2	\N
3	Resolved	f	3	\N
4	Feedback	f	4	\N
5	Closed	t	5	\N
6	Rejected	t	6	\N
7	New - Verify	f	7	\N
8	Reopened	f	8	\N
9	Confirmed	f	9	\N
\.


--
-- Data for Name: issues; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.issues (id, tracker_id, project_id, subject, description, due_date, category_id, status_id, assigned_to_id, priority_id, fixed_version_id, author_id, lock_version, created_on, updated_on, start_date, done_ratio, estimated_hours, parent_id, root_id, lft, rgt, is_private, closed_on) FROM stdin;
1	6	1	Inadequeate error handler	generic_error_disclosure	\N	\N	9	1	1	\N	1	1	2020-11-13 15:47:08.770919	2020-11-13 15:48:38.00195	\N	0	\N	\N	1	1	2	f	\N
2	6	1	Inadequeate error handler	generic_error_disclosure	\N	\N	9	1	1	\N	1	1	2020-11-13 15:47:08.774981	2020-11-13 15:48:38.108488	\N	0	\N	\N	2	1	2	f	\N
3	6	1	Inadequeate error handler	generic_error_disclosure	\N	\N	9	1	1	\N	1	1	2020-11-13 15:47:08.779125	2020-11-13 15:48:38.211727	\N	0	\N	\N	3	1	2	f	\N
4	6	1	Inadequeate error handler	generic_error_disclosure	\N	\N	9	1	1	\N	1	1	2020-11-13 15:47:08.783747	2020-11-13 15:48:38.368081	\N	0	\N	\N	4	1	2	f	\N
5	6	1	Inadequeate error handler	generic_error_disclosure	\N	\N	9	1	1	\N	1	1	2020-11-13 15:47:09.850982	2020-11-13 15:48:38.58964	\N	0	\N	\N	5	1	2	f	\N
6	6	1	Inadequeate error handler	generic_error_disclosure	\N	\N	9	1	1	\N	1	1	2020-11-13 15:47:09.999771	2020-11-13 15:48:38.71086	\N	0	\N	\N	6	1	2	f	\N
7	6	1	Inadequeate error handler	generic_error_disclosure	\N	\N	9	1	1	\N	1	1	2020-11-13 15:47:10.023163	2020-11-13 15:48:38.867744	\N	0	\N	\N	7	1	2	f	\N
8	6	1	Inadequeate error handler	generic_error_disclosure	\N	\N	9	1	1	\N	1	1	2020-11-13 15:47:10.028134	2020-11-13 15:48:39.080978	\N	0	\N	\N	8	1	2	f	\N
9	6	1	Inadequeate error handler	generic_error_disclosure	\N	\N	9	1	1	\N	1	1	2020-11-13 15:47:11.323652	2020-11-13 15:48:39.269495	\N	0	\N	\N	9	1	2	f	\N
10	6	1	Inadequeate error handler	generic_error_disclosure	\N	\N	9	1	1	\N	1	1	2020-11-13 15:47:11.48232	2020-11-13 15:48:39.407675	\N	0	\N	\N	10	1	2	f	\N
11	6	1	Inadequeate error handler	generic_error_disclosure	\N	\N	9	1	1	\N	1	1	2020-11-13 15:47:11.623153	2020-11-13 15:48:39.526149	\N	0	\N	\N	11	1	2	f	\N
12	6	1	Insecure random generator	node_insecure_random_generator	\N	\N	9	1	1	\N	1	1	2020-11-13 15:47:11.682992	2020-11-13 15:48:39.641753	\N	0	\N	\N	12	1	2	f	\N
13	6	1	Insecure random generator	node_insecure_random_generator	\N	\N	9	1	1	\N	1	1	2020-11-13 15:47:13.658662	2020-11-13 15:48:39.765136	\N	0	\N	\N	13	1	2	f	\N
14	6	1	Insecure random generator	node_insecure_random_generator	\N	\N	9	1	1	\N	1	1	2020-11-13 15:47:13.893891	2020-11-13 15:48:39.926788	\N	0	\N	\N	14	1	2	f	\N
15	6	1	A hardcoded password in plain text is identified. Store it properly in an environment variable.	node_password	\N	\N	9	1	11	\N	1	1	2020-11-13 15:47:14.158385	2020-11-13 15:48:40.036179	\N	0	\N	\N	15	1	2	f	\N
16	6	1	Insecure random generator	node_insecure_random_generator	\N	\N	9	1	1	\N	1	1	2020-11-13 15:47:14.169631	2020-11-13 15:48:40.188838	\N	0	\N	\N	16	1	2	f	\N
17	6	1	A hardcoded username in plain text is identified. Store it properly in an environment variable.	node_username	\N	\N	9	1	11	\N	1	1	2020-11-13 15:47:16.300516	2020-11-13 15:48:40.294017	\N	0	\N	\N	17	1	2	f	\N
18	6	1	A hardcoded username in plain text is identified. Store it properly in an environment variable.	node_username	\N	\N	9	1	11	\N	1	1	2020-11-13 15:47:16.502063	2020-11-13 15:48:40.407875	\N	0	\N	\N	18	1	2	f	\N
19	6	1	Potentially sensitive information in localstorage	Potentially sensitive information in localstorage	\N	\N	9	1	1	\N	1	1	2020-11-13 15:47:16.633944	2020-11-13 15:48:40.536075	\N	0	\N	\N	19	1	2	f	\N
\.


--
-- Data for Name: journal_details; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.journal_details (id, journal_id, property, prop_key, old_value, value) FROM stdin;
3	3	attr	status_id	1	9
4	4	attr	status_id	1	9
5	5	attr	status_id	1	9
6	6	attr	status_id	1	9
7	7	attr	status_id	1	9
8	8	attr	status_id	1	9
9	9	attr	status_id	1	9
10	10	attr	status_id	1	9
11	11	attr	status_id	1	9
12	12	attr	status_id	1	9
13	13	attr	status_id	1	9
14	14	attr	status_id	1	9
15	15	attr	status_id	1	9
16	16	attr	status_id	1	9
17	17	attr	status_id	1	9
18	18	attr	status_id	1	9
19	19	attr	status_id	1	9
20	20	attr	status_id	1	9
21	21	attr	status_id	1	9
\.


--
-- Data for Name: journals; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.journals (id, journalized_id, journalized_type, user_id, notes, created_on, private_notes) FROM stdin;
3	1	Issue	1	\N	2020-11-13 15:48:38.040991	f
4	2	Issue	1	\N	2020-11-13 15:48:38.12095	f
5	3	Issue	1	\N	2020-11-13 15:48:38.223606	f
6	4	Issue	1	\N	2020-11-13 15:48:38.384441	f
7	5	Issue	1	\N	2020-11-13 15:48:38.623225	f
8	6	Issue	1	\N	2020-11-13 15:48:38.721983	f
9	7	Issue	1	\N	2020-11-13 15:48:38.897291	f
10	8	Issue	1	\N	2020-11-13 15:48:39.098288	f
11	9	Issue	1	\N	2020-11-13 15:48:39.298071	f
12	10	Issue	1	\N	2020-11-13 15:48:39.428026	f
13	11	Issue	1	\N	2020-11-13 15:48:39.539711	f
14	12	Issue	1	\N	2020-11-13 15:48:39.658326	f
15	13	Issue	1	\N	2020-11-13 15:48:39.780376	f
16	14	Issue	1	\N	2020-11-13 15:48:39.940611	f
17	15	Issue	1	\N	2020-11-13 15:48:40.059299	f
18	16	Issue	1	\N	2020-11-13 15:48:40.201764	f
19	17	Issue	1	\N	2020-11-13 15:48:40.317921	f
20	18	Issue	1	\N	2020-11-13 15:48:40.418207	f
21	19	Issue	1	\N	2020-11-13 15:48:40.549192	f
\.


--
-- Data for Name: member_roles; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.member_roles (id, member_id, role_id, inherited_from) FROM stdin;
\.


--
-- Data for Name: members; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.members (id, user_id, project_id, created_on, mail_notification) FROM stdin;
\.


--
-- Data for Name: messages; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.messages (id, board_id, parent_id, subject, content, author_id, replies_count, last_reply_id, created_on, updated_on, locked, sticky) FROM stdin;
\.


--
-- Data for Name: news; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.news (id, project_id, title, summary, description, author_id, created_on, comments_count) FROM stdin;
\.


--
-- Data for Name: open_id_authentication_associations; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.open_id_authentication_associations (id, issued, lifetime, handle, assoc_type, server_url, secret) FROM stdin;
\.


--
-- Data for Name: open_id_authentication_nonces; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.open_id_authentication_nonces (id, "timestamp", server_url, salt) FROM stdin;
\.


--
-- Data for Name: projects; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.projects (id, name, description, homepage, is_public, parent_id, created_on, updated_on, identifier, status, lft, rgt, inherit_members, default_version_id, default_assigned_to_id) FROM stdin;
1	TestProject			t	\N	2020-11-13 15:42:01.192458	2020-11-13 15:42:01.192458	testproject	1	1	2	f	\N	\N
\.


--
-- Data for Name: projects_trackers; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.projects_trackers (project_id, tracker_id) FROM stdin;
1	4
1	5
1	6
\.


--
-- Data for Name: queries; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.queries (id, project_id, name, filters, user_id, column_names, sort_criteria, group_by, type, visibility, options) FROM stdin;
\.


--
-- Data for Name: queries_roles; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.queries_roles (query_id, role_id) FROM stdin;
\.


--
-- Data for Name: repositories; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.repositories (id, project_id, url, login, password, root_url, type, path_encoding, log_encoding, extra_info, identifier, is_default, created_on) FROM stdin;
\.


--
-- Data for Name: roles; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.roles (id, name, "position", assignable, builtin, permissions, issues_visibility, users_visibility, time_entries_visibility, all_roles_managed, settings) FROM stdin;
3	Manager	1	t	0	---\n- :add_project\n- :edit_project\n- :close_project\n- :select_project_modules\n- :manage_members\n- :manage_versions\n- :add_subprojects\n- :manage_public_queries\n- :save_queries\n- :view_issues\n- :add_issues\n- :edit_issues\n- :edit_own_issues\n- :copy_issues\n- :manage_issue_relations\n- :manage_subtasks\n- :set_issues_private\n- :set_own_issues_private\n- :add_issue_notes\n- :edit_issue_notes\n- :edit_own_issue_notes\n- :view_private_notes\n- :set_notes_private\n- :delete_issues\n- :view_issue_watchers\n- :add_issue_watchers\n- :delete_issue_watchers\n- :import_issues\n- :manage_categories\n- :view_time_entries\n- :log_time\n- :edit_time_entries\n- :edit_own_time_entries\n- :manage_project_activities\n- :log_time_for_other_users\n- :import_time_entries\n- :view_news\n- :manage_news\n- :comment_news\n- :view_documents\n- :add_documents\n- :edit_documents\n- :delete_documents\n- :view_files\n- :manage_files\n- :view_wiki_pages\n- :view_wiki_edits\n- :export_wiki_pages\n- :edit_wiki_pages\n- :rename_wiki_pages\n- :delete_wiki_pages\n- :delete_wiki_pages_attachments\n- :protect_wiki_pages\n- :manage_wiki\n- :view_changesets\n- :browse_repository\n- :commit_access\n- :manage_related_issues\n- :manage_repository\n- :view_messages\n- :add_messages\n- :edit_messages\n- :edit_own_messages\n- :delete_messages\n- :delete_own_messages\n- :manage_boards\n- :view_calendar\n- :view_gantt\n	all	all	all	t	\N
4	Developer	2	t	0	---\n- :manage_versions\n- :manage_categories\n- :view_issues\n- :add_issues\n- :edit_issues\n- :view_private_notes\n- :set_notes_private\n- :manage_issue_relations\n- :manage_subtasks\n- :add_issue_notes\n- :save_queries\n- :view_gantt\n- :view_calendar\n- :log_time\n- :view_time_entries\n- :view_news\n- :comment_news\n- :view_documents\n- :view_wiki_pages\n- :view_wiki_edits\n- :edit_wiki_pages\n- :delete_wiki_pages\n- :view_messages\n- :add_messages\n- :edit_own_messages\n- :view_files\n- :manage_files\n- :browse_repository\n- :view_changesets\n- :commit_access\n- :manage_related_issues\n	default	all	all	t	\N
5	Reporter	3	t	0	---\n- :view_issues\n- :add_issues\n- :add_issue_notes\n- :save_queries\n- :view_gantt\n- :view_calendar\n- :log_time\n- :view_time_entries\n- :view_news\n- :comment_news\n- :view_documents\n- :view_wiki_pages\n- :view_wiki_edits\n- :view_messages\n- :add_messages\n- :edit_own_messages\n- :view_files\n- :browse_repository\n- :view_changesets\n	default	all	all	t	\N
1	Non member	0	t	1	---\n- :view_issues\n- :add_issues\n- :add_issue_notes\n- :save_queries\n- :view_gantt\n- :view_calendar\n- :view_time_entries\n- :view_news\n- :comment_news\n- :view_documents\n- :view_wiki_pages\n- :view_wiki_edits\n- :view_messages\n- :add_messages\n- :view_files\n- :browse_repository\n- :view_changesets\n	default	all	all	t	\N
2	Anonymous	0	t	2	---\n- :view_issues\n- :view_gantt\n- :view_calendar\n- :view_time_entries\n- :view_news\n- :view_documents\n- :view_wiki_pages\n- :view_wiki_edits\n- :view_messages\n- :view_files\n- :browse_repository\n- :view_changesets\n	default	all	all	t	\N
\.


--
-- Data for Name: roles_managed_roles; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.roles_managed_roles (role_id, managed_role_id) FROM stdin;
\.


--
-- Data for Name: schema_migrations; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.schema_migrations (version) FROM stdin;
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
44
45
46
47
48
49
50
51
52
53
54
55
56
57
58
59
60
61
62
63
64
65
66
67
68
69
70
71
72
73
74
75
76
77
78
79
80
81
82
83
84
85
86
87
88
89
90
91
92
93
94
95
96
97
98
99
100
101
102
103
104
105
106
107
108
20090214190337
20090312172426
20090312194159
20090318181151
20090323224724
20090401221305
20090401231134
20090403001910
20090406161854
20090425161243
20090503121501
20090503121505
20090503121510
20090614091200
20090704172350
20090704172355
20090704172358
20091010093521
20091017212227
20091017212457
20091017212644
20091017212938
20091017213027
20091017213113
20091017213151
20091017213228
20091017213257
20091017213332
20091017213444
20091017213536
20091017213642
20091017213716
20091017213757
20091017213835
20091017213910
20091017214015
20091017214107
20091017214136
20091017214236
20091017214308
20091017214336
20091017214406
20091017214440
20091017214519
20091017214611
20091017214644
20091017214720
20091017214750
20091025163651
20091108092559
20091114105931
20091123212029
20091205124427
20091220183509
20091220183727
20091220184736
20091225164732
20091227112908
20100129193402
20100129193813
20100221100219
20100313132032
20100313171051
20100705164950
20100819172912
20101104182107
20101107130441
20101114115114
20101114115359
20110220160626
20110223180944
20110223180953
20110224000000
20110226120112
20110226120132
20110227125750
20110228000000
20110228000100
20110401192910
20110408103312
20110412065600
20110511000000
20110902000000
20111201201315
20120115143024
20120115143100
20120115143126
20120127174243
20120205111326
20120223110929
20120301153455
20120422150750
20120705074331
20120707064544
20120714122000
20120714122100
20120714122200
20120731164049
20120930112914
20121026002032
20121026003537
20121209123234
20121209123358
20121213084931
20130110122628
20130201184705
20130202090625
20130207175206
20130207181455
20130215073721
20130215111127
20130215111141
20130217094251
20130602092539
20130710182539
20130713104233
20130713111657
20130729070143
20130911193200
20131004113137
20131005100610
20131124175346
20131210180802
20131214094309
20131215104612
20131218183023
20140228130325
20140903143914
20140920094058
20141029181752
20141029181824
20141109112308
20141122124142
20150113194759
20150113211532
20150113213922
20150113213955
20150208105930
20150510083747
20150525103953
20150526183158
20150528084820
20150528092912
20150528093249
20150725112753
20150730122707
20150730122735
20150921204850
20150921210243
20151020182334
20151020182731
20151021184614
20151021185456
20151021190616
20151024082034
20151025072118
20151031095005
20160404080304
20160416072926
20160529063352
20161001122012
20161002133421
20161010081301
20161010081528
20161010081600
20161126094932
20161220091118
20170207050700
20170302015225
20170309214320
20170320051650
20170418090031
20170419144536
20170723112801
20180501132547
20180913072918
20180923082945
20180923091603
20190315094151
20190315102101
20190510070108
20190620135549
\.


--
-- Data for Name: settings; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.settings (id, name, value, updated_on) FROM stdin;
1	rest_api_enabled	1	2020-09-07 15:32:47.11848
2	jsonp_enabled	0	2020-09-07 15:32:47.128196
\.


--
-- Data for Name: time_entries; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.time_entries (id, project_id, user_id, issue_id, hours, comments, activity_id, spent_on, tyear, tmonth, tweek, created_on, updated_on, author_id) FROM stdin;
\.


--
-- Data for Name: tokens; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.tokens (id, user_id, action, value, created_on, updated_on) FROM stdin;
3	1	feeds	4ef72eac51ad3f74f17178bdc24dad864ade626f	2020-09-04 18:09:23.047979	2020-09-04 18:09:23.047979
5	1	session	c3e91bd66150ca13f0a66f991b5b5d75de4daa30	2020-09-04 18:20:47.131534	2020-09-04 18:23:51.003027
6	1	session	73521259d67fe1307edccf7b4392bc48b45f2cef	2020-09-07 13:19:27.939728	2020-09-07 13:19:28.449459
7	1	session	4261f892cc94104f05a4efe4eb5530a291e520bf	2020-09-07 13:24:26.659601	2020-09-07 15:46:30.216844
2	1	session	45de0e46c1e70a16c8a3d0892c426a67951137ef	2020-09-04 16:40:19.883545	2020-09-07 15:53:47.890203
8	1	session	ee56387d2b70dcbdd52ddb2b84f4eea629cd472e	2020-09-07 15:55:19.862962	2020-09-07 18:36:35.801304
9	1	session	fdb386c9500980810b67586e798dd952099e1823	2020-09-09 19:10:45.847781	2020-09-09 19:11:32.885546
11	1	session	a1ab0253f36ae0e9fb5a6357ccacd8bbc09d6c21	2020-09-10 16:22:01.357377	2020-09-10 16:24:23.808049
10	1	session	e15c953a13ae345858674730fae0a2a708f9b17b	2020-09-10 16:20:51.181361	2020-09-10 16:52:53.694764
12	1	session	269e1e8425074bb727f907198b9a0913afe951d1	2020-11-13 15:37:58.816945	2020-11-13 15:52:59.875674
\.


--
-- Data for Name: trackers; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.trackers (id, name, is_in_chlog, "position", is_in_roadmap, fields_bits, default_status_id, description) FROM stdin;
4	Web Finding	f	1	t	252	1	
5	Infra Finding	f	2	t	252	1	
6	Code Finding	f	3	t	252	1	
\.


--
-- Data for Name: user_preferences; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.user_preferences (id, user_id, others, hide_mail, time_zone) FROM stdin;
1	1	---\n:no_self_notified: true\n:my_page_layout:\n  left:\n  - issuesassignedtome\n  right:\n  - issuesreportedbyme\n:my_page_settings: {}\n:recently_used_project_ids: '1'\n	t	
\.


--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.users (id, login, hashed_password, firstname, lastname, admin, status, last_login_on, language, auth_source_id, created_on, updated_on, type, identity_url, mail_notification, salt, must_change_passwd, passwd_changed_on) FROM stdin;
2				Anonymous users	f	1	\N		\N	2020-09-04 16:38:12.582871	2020-09-04 16:38:12.582871	GroupAnonymous	\N		\N	f	\N
3				Non member users	f	1	\N		\N	2020-09-04 16:38:12.661368	2020-09-04 16:38:12.661368	GroupNonMember	\N		\N	f	\N
4				Anonymous	f	0	\N		\N	2020-09-04 16:38:21.328527	2020-09-04 16:38:21.328527	AnonymousUser	\N	only_my_events	\N	f	\N
1	admin	c28dd339002ef77f41f906b37c981a6092e96df3	Redmine	Admin	t	1	2020-11-13 15:49:23.252495		\N	2020-09-04 16:38:05.505611	2020-09-04 16:40:19.852077	User	\N	all	e0aecc28f14936ad507b533cdd772a87	f	2020-09-04 16:40:19
\.


--
-- Data for Name: versions; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.versions (id, project_id, name, description, effective_date, created_on, updated_on, wiki_page_title, status, sharing) FROM stdin;
\.


--
-- Data for Name: watchers; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.watchers (id, watchable_type, watchable_id, user_id) FROM stdin;
7	Issue	4	1
8	Issue	1	1
9	Issue	3	1
10	Issue	2	1
11	Issue	5	1
12	Issue	6	1
13	Issue	8	1
14	Issue	7	1
15	Issue	9	1
16	Issue	10	1
17	Issue	11	1
18	Issue	12	1
19	Issue	13	1
20	Issue	14	1
21	Issue	16	1
22	Issue	15	1
23	Issue	17	1
24	Issue	18	1
25	Issue	19	1
\.


--
-- Data for Name: wiki_content_versions; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.wiki_content_versions (id, wiki_content_id, page_id, author_id, data, compression, comments, updated_on, version) FROM stdin;
\.


--
-- Data for Name: wiki_contents; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.wiki_contents (id, page_id, author_id, text, comments, updated_on, version) FROM stdin;
\.


--
-- Data for Name: wiki_pages; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.wiki_pages (id, wiki_id, title, created_on, protected, parent_id) FROM stdin;
\.


--
-- Data for Name: wiki_redirects; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.wiki_redirects (id, wiki_id, title, redirects_to, created_on, redirects_to_wiki_id) FROM stdin;
\.


--
-- Data for Name: wikis; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.wikis (id, project_id, start_page, status) FROM stdin;
2	1	Wiki	1
\.


--
-- Data for Name: workflows; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.workflows (id, tracker_id, old_status_id, new_status_id, role_id, assignee, author, type, field_name, rule) FROM stdin;
484	4	9	1	3	f	f	WorkflowTransition	\N	\N
485	4	9	1	4	f	f	WorkflowTransition	\N	\N
486	4	9	1	5	f	f	WorkflowTransition	\N	\N
487	4	9	1	1	f	f	WorkflowTransition	\N	\N
488	5	9	1	3	f	f	WorkflowTransition	\N	\N
489	5	9	1	4	f	f	WorkflowTransition	\N	\N
490	5	9	1	5	f	f	WorkflowTransition	\N	\N
491	5	9	1	1	f	f	WorkflowTransition	\N	\N
492	6	9	1	3	f	f	WorkflowTransition	\N	\N
493	6	9	1	4	f	f	WorkflowTransition	\N	\N
494	6	9	1	5	f	f	WorkflowTransition	\N	\N
495	6	9	1	1	f	f	WorkflowTransition	\N	\N
496	4	9	2	3	f	f	WorkflowTransition	\N	\N
497	4	9	2	4	f	f	WorkflowTransition	\N	\N
498	4	9	2	5	f	f	WorkflowTransition	\N	\N
499	4	9	2	1	f	f	WorkflowTransition	\N	\N
500	5	9	2	3	f	f	WorkflowTransition	\N	\N
501	5	9	2	4	f	f	WorkflowTransition	\N	\N
502	5	9	2	5	f	f	WorkflowTransition	\N	\N
503	5	9	2	1	f	f	WorkflowTransition	\N	\N
504	6	9	2	3	f	f	WorkflowTransition	\N	\N
505	6	9	2	4	f	f	WorkflowTransition	\N	\N
506	6	9	2	5	f	f	WorkflowTransition	\N	\N
507	6	9	2	1	f	f	WorkflowTransition	\N	\N
508	4	9	3	3	f	f	WorkflowTransition	\N	\N
509	4	9	3	4	f	f	WorkflowTransition	\N	\N
510	4	9	3	5	f	f	WorkflowTransition	\N	\N
511	4	9	3	1	f	f	WorkflowTransition	\N	\N
512	5	9	3	3	f	f	WorkflowTransition	\N	\N
513	5	9	3	4	f	f	WorkflowTransition	\N	\N
514	5	9	3	5	f	f	WorkflowTransition	\N	\N
515	5	9	3	1	f	f	WorkflowTransition	\N	\N
516	6	9	3	3	f	f	WorkflowTransition	\N	\N
517	6	9	3	4	f	f	WorkflowTransition	\N	\N
518	6	9	3	5	f	f	WorkflowTransition	\N	\N
519	6	9	3	1	f	f	WorkflowTransition	\N	\N
520	4	9	5	3	f	f	WorkflowTransition	\N	\N
521	4	9	5	4	f	f	WorkflowTransition	\N	\N
522	4	9	5	5	f	f	WorkflowTransition	\N	\N
523	4	9	5	1	f	f	WorkflowTransition	\N	\N
524	5	9	5	3	f	f	WorkflowTransition	\N	\N
525	5	9	5	4	f	f	WorkflowTransition	\N	\N
526	5	9	5	5	f	f	WorkflowTransition	\N	\N
527	5	9	5	1	f	f	WorkflowTransition	\N	\N
528	6	9	5	3	f	f	WorkflowTransition	\N	\N
529	6	9	5	4	f	f	WorkflowTransition	\N	\N
530	6	9	5	5	f	f	WorkflowTransition	\N	\N
531	6	9	5	1	f	f	WorkflowTransition	\N	\N
532	4	9	6	3	f	f	WorkflowTransition	\N	\N
533	4	9	6	4	f	f	WorkflowTransition	\N	\N
534	4	9	6	5	f	f	WorkflowTransition	\N	\N
535	4	9	6	1	f	f	WorkflowTransition	\N	\N
536	5	9	6	3	f	f	WorkflowTransition	\N	\N
537	5	9	6	4	f	f	WorkflowTransition	\N	\N
538	5	9	6	5	f	f	WorkflowTransition	\N	\N
539	5	9	6	1	f	f	WorkflowTransition	\N	\N
540	6	9	6	3	f	f	WorkflowTransition	\N	\N
541	6	9	6	4	f	f	WorkflowTransition	\N	\N
542	6	9	6	5	f	f	WorkflowTransition	\N	\N
543	6	9	6	1	f	f	WorkflowTransition	\N	\N
544	4	9	7	3	f	f	WorkflowTransition	\N	\N
545	4	9	7	4	f	f	WorkflowTransition	\N	\N
546	4	9	7	5	f	f	WorkflowTransition	\N	\N
547	4	9	7	1	f	f	WorkflowTransition	\N	\N
548	5	9	7	3	f	f	WorkflowTransition	\N	\N
549	5	9	7	4	f	f	WorkflowTransition	\N	\N
550	5	9	7	5	f	f	WorkflowTransition	\N	\N
551	5	9	7	1	f	f	WorkflowTransition	\N	\N
552	6	9	7	3	f	f	WorkflowTransition	\N	\N
553	6	9	7	4	f	f	WorkflowTransition	\N	\N
554	6	9	7	5	f	f	WorkflowTransition	\N	\N
555	6	9	7	1	f	f	WorkflowTransition	\N	\N
145	4	1	2	3	f	f	WorkflowTransition	\N	\N
146	4	1	2	4	f	f	WorkflowTransition	\N	\N
147	4	1	2	5	f	f	WorkflowTransition	\N	\N
148	4	1	2	1	f	f	WorkflowTransition	\N	\N
149	4	1	3	3	f	f	WorkflowTransition	\N	\N
150	4	1	3	4	f	f	WorkflowTransition	\N	\N
151	4	1	3	5	f	f	WorkflowTransition	\N	\N
152	4	1	3	1	f	f	WorkflowTransition	\N	\N
153	4	1	5	3	f	f	WorkflowTransition	\N	\N
154	4	1	5	4	f	f	WorkflowTransition	\N	\N
155	4	1	5	5	f	f	WorkflowTransition	\N	\N
156	4	1	5	1	f	f	WorkflowTransition	\N	\N
157	4	1	6	3	f	f	WorkflowTransition	\N	\N
158	4	1	6	4	f	f	WorkflowTransition	\N	\N
159	4	1	6	5	f	f	WorkflowTransition	\N	\N
160	4	1	6	1	f	f	WorkflowTransition	\N	\N
161	4	2	5	3	f	f	WorkflowTransition	\N	\N
162	4	2	5	4	f	f	WorkflowTransition	\N	\N
163	4	2	5	5	f	f	WorkflowTransition	\N	\N
164	4	2	5	1	f	f	WorkflowTransition	\N	\N
165	4	2	6	3	f	f	WorkflowTransition	\N	\N
166	4	2	6	4	f	f	WorkflowTransition	\N	\N
167	4	2	6	5	f	f	WorkflowTransition	\N	\N
168	4	2	6	1	f	f	WorkflowTransition	\N	\N
169	4	3	5	3	f	f	WorkflowTransition	\N	\N
170	4	3	5	4	f	f	WorkflowTransition	\N	\N
171	4	3	5	5	f	f	WorkflowTransition	\N	\N
172	4	3	5	1	f	f	WorkflowTransition	\N	\N
173	4	3	6	3	f	f	WorkflowTransition	\N	\N
174	4	3	6	4	f	f	WorkflowTransition	\N	\N
175	4	3	6	5	f	f	WorkflowTransition	\N	\N
176	4	3	6	1	f	f	WorkflowTransition	\N	\N
177	4	3	8	3	f	f	WorkflowTransition	\N	\N
178	4	3	8	4	f	f	WorkflowTransition	\N	\N
179	4	3	8	5	f	f	WorkflowTransition	\N	\N
180	4	3	8	1	f	f	WorkflowTransition	\N	\N
181	4	5	1	3	f	f	WorkflowTransition	\N	\N
182	4	5	1	4	f	f	WorkflowTransition	\N	\N
183	4	5	1	5	f	f	WorkflowTransition	\N	\N
184	4	5	1	1	f	f	WorkflowTransition	\N	\N
185	4	5	7	3	f	f	WorkflowTransition	\N	\N
186	4	5	7	4	f	f	WorkflowTransition	\N	\N
187	4	5	7	5	f	f	WorkflowTransition	\N	\N
188	4	5	7	1	f	f	WorkflowTransition	\N	\N
189	4	6	1	3	f	f	WorkflowTransition	\N	\N
190	4	6	1	4	f	f	WorkflowTransition	\N	\N
191	4	6	1	5	f	f	WorkflowTransition	\N	\N
192	4	6	1	1	f	f	WorkflowTransition	\N	\N
193	4	6	7	3	f	f	WorkflowTransition	\N	\N
194	4	6	7	4	f	f	WorkflowTransition	\N	\N
195	4	6	7	5	f	f	WorkflowTransition	\N	\N
196	4	6	7	1	f	f	WorkflowTransition	\N	\N
197	4	7	2	3	f	f	WorkflowTransition	\N	\N
198	4	7	2	4	f	f	WorkflowTransition	\N	\N
199	4	7	2	5	f	f	WorkflowTransition	\N	\N
200	4	7	2	1	f	f	WorkflowTransition	\N	\N
201	4	7	3	3	f	f	WorkflowTransition	\N	\N
202	4	7	3	4	f	f	WorkflowTransition	\N	\N
203	4	7	3	5	f	f	WorkflowTransition	\N	\N
204	4	7	3	1	f	f	WorkflowTransition	\N	\N
205	4	7	5	3	f	f	WorkflowTransition	\N	\N
206	4	7	5	4	f	f	WorkflowTransition	\N	\N
207	4	7	5	5	f	f	WorkflowTransition	\N	\N
208	4	7	5	1	f	f	WorkflowTransition	\N	\N
209	4	7	6	3	f	f	WorkflowTransition	\N	\N
210	4	7	6	4	f	f	WorkflowTransition	\N	\N
211	4	7	6	5	f	f	WorkflowTransition	\N	\N
212	4	7	6	1	f	f	WorkflowTransition	\N	\N
213	4	7	8	3	f	f	WorkflowTransition	\N	\N
214	4	7	8	4	f	f	WorkflowTransition	\N	\N
215	4	7	8	5	f	f	WorkflowTransition	\N	\N
216	4	7	8	1	f	f	WorkflowTransition	\N	\N
217	4	8	1	3	f	f	WorkflowTransition	\N	\N
218	4	8	1	4	f	f	WorkflowTransition	\N	\N
219	4	8	1	5	f	f	WorkflowTransition	\N	\N
220	4	8	1	1	f	f	WorkflowTransition	\N	\N
221	4	8	2	3	f	f	WorkflowTransition	\N	\N
222	4	8	2	4	f	f	WorkflowTransition	\N	\N
223	4	8	2	5	f	f	WorkflowTransition	\N	\N
224	4	8	2	1	f	f	WorkflowTransition	\N	\N
225	4	8	3	3	f	f	WorkflowTransition	\N	\N
226	4	8	3	4	f	f	WorkflowTransition	\N	\N
227	4	8	3	5	f	f	WorkflowTransition	\N	\N
228	4	8	3	1	f	f	WorkflowTransition	\N	\N
229	4	8	5	3	f	f	WorkflowTransition	\N	\N
230	4	8	5	4	f	f	WorkflowTransition	\N	\N
231	4	8	5	5	f	f	WorkflowTransition	\N	\N
232	4	8	5	1	f	f	WorkflowTransition	\N	\N
233	4	8	6	3	f	f	WorkflowTransition	\N	\N
234	4	8	6	4	f	f	WorkflowTransition	\N	\N
235	4	8	6	5	f	f	WorkflowTransition	\N	\N
236	4	8	6	1	f	f	WorkflowTransition	\N	\N
237	4	8	7	3	f	f	WorkflowTransition	\N	\N
238	4	8	7	4	f	f	WorkflowTransition	\N	\N
239	4	8	7	5	f	f	WorkflowTransition	\N	\N
240	4	8	7	1	f	f	WorkflowTransition	\N	\N
241	5	1	2	3	f	f	WorkflowTransition	\N	\N
242	5	1	2	4	f	f	WorkflowTransition	\N	\N
243	5	1	2	5	f	f	WorkflowTransition	\N	\N
244	5	1	2	1	f	f	WorkflowTransition	\N	\N
245	5	1	3	3	f	f	WorkflowTransition	\N	\N
246	5	1	3	4	f	f	WorkflowTransition	\N	\N
247	5	1	3	5	f	f	WorkflowTransition	\N	\N
248	5	1	3	1	f	f	WorkflowTransition	\N	\N
249	5	1	5	3	f	f	WorkflowTransition	\N	\N
250	5	1	5	4	f	f	WorkflowTransition	\N	\N
251	5	1	5	5	f	f	WorkflowTransition	\N	\N
252	5	1	5	1	f	f	WorkflowTransition	\N	\N
253	5	1	6	3	f	f	WorkflowTransition	\N	\N
254	5	1	6	4	f	f	WorkflowTransition	\N	\N
255	5	1	6	5	f	f	WorkflowTransition	\N	\N
256	5	1	6	1	f	f	WorkflowTransition	\N	\N
257	5	1	7	3	f	f	WorkflowTransition	\N	\N
258	5	1	7	4	f	f	WorkflowTransition	\N	\N
259	5	1	7	5	f	f	WorkflowTransition	\N	\N
260	5	1	7	1	f	f	WorkflowTransition	\N	\N
261	5	2	5	3	f	f	WorkflowTransition	\N	\N
262	5	2	5	4	f	f	WorkflowTransition	\N	\N
263	5	2	5	5	f	f	WorkflowTransition	\N	\N
264	5	2	5	1	f	f	WorkflowTransition	\N	\N
265	5	2	6	3	f	f	WorkflowTransition	\N	\N
266	5	2	6	4	f	f	WorkflowTransition	\N	\N
267	5	2	6	5	f	f	WorkflowTransition	\N	\N
268	5	2	6	1	f	f	WorkflowTransition	\N	\N
269	5	2	7	3	f	f	WorkflowTransition	\N	\N
270	5	2	7	4	f	f	WorkflowTransition	\N	\N
271	5	2	7	5	f	f	WorkflowTransition	\N	\N
272	5	2	7	1	f	f	WorkflowTransition	\N	\N
273	5	3	5	3	f	f	WorkflowTransition	\N	\N
274	5	3	5	4	f	f	WorkflowTransition	\N	\N
275	5	3	5	5	f	f	WorkflowTransition	\N	\N
276	5	3	5	1	f	f	WorkflowTransition	\N	\N
277	5	3	6	3	f	f	WorkflowTransition	\N	\N
278	5	3	6	4	f	f	WorkflowTransition	\N	\N
279	5	3	6	5	f	f	WorkflowTransition	\N	\N
280	5	3	6	1	f	f	WorkflowTransition	\N	\N
281	5	3	7	3	f	f	WorkflowTransition	\N	\N
282	5	3	7	4	f	f	WorkflowTransition	\N	\N
283	5	3	7	5	f	f	WorkflowTransition	\N	\N
284	5	3	7	1	f	f	WorkflowTransition	\N	\N
285	5	3	8	3	f	f	WorkflowTransition	\N	\N
286	5	3	8	4	f	f	WorkflowTransition	\N	\N
287	5	3	8	5	f	f	WorkflowTransition	\N	\N
288	5	3	8	1	f	f	WorkflowTransition	\N	\N
289	5	5	1	3	f	f	WorkflowTransition	\N	\N
290	5	5	1	4	f	f	WorkflowTransition	\N	\N
291	5	5	1	5	f	f	WorkflowTransition	\N	\N
292	5	5	1	1	f	f	WorkflowTransition	\N	\N
293	5	5	7	3	f	f	WorkflowTransition	\N	\N
294	5	5	7	4	f	f	WorkflowTransition	\N	\N
295	5	5	7	5	f	f	WorkflowTransition	\N	\N
296	5	5	7	1	f	f	WorkflowTransition	\N	\N
297	5	6	1	3	f	f	WorkflowTransition	\N	\N
298	5	6	1	4	f	f	WorkflowTransition	\N	\N
299	5	6	1	5	f	f	WorkflowTransition	\N	\N
300	5	6	1	1	f	f	WorkflowTransition	\N	\N
301	5	6	7	3	f	f	WorkflowTransition	\N	\N
302	5	6	7	4	f	f	WorkflowTransition	\N	\N
303	5	6	7	5	f	f	WorkflowTransition	\N	\N
304	5	6	7	1	f	f	WorkflowTransition	\N	\N
305	5	7	2	3	f	f	WorkflowTransition	\N	\N
306	5	7	2	4	f	f	WorkflowTransition	\N	\N
307	5	7	2	5	f	f	WorkflowTransition	\N	\N
308	5	7	2	1	f	f	WorkflowTransition	\N	\N
309	5	7	3	3	f	f	WorkflowTransition	\N	\N
310	5	7	3	4	f	f	WorkflowTransition	\N	\N
311	5	7	3	5	f	f	WorkflowTransition	\N	\N
312	5	7	3	1	f	f	WorkflowTransition	\N	\N
313	5	7	5	3	f	f	WorkflowTransition	\N	\N
314	5	7	5	4	f	f	WorkflowTransition	\N	\N
315	5	7	5	5	f	f	WorkflowTransition	\N	\N
316	5	7	5	1	f	f	WorkflowTransition	\N	\N
317	5	7	6	3	f	f	WorkflowTransition	\N	\N
318	5	7	6	4	f	f	WorkflowTransition	\N	\N
319	5	7	6	5	f	f	WorkflowTransition	\N	\N
320	5	7	6	1	f	f	WorkflowTransition	\N	\N
321	5	8	1	3	f	f	WorkflowTransition	\N	\N
322	5	8	1	4	f	f	WorkflowTransition	\N	\N
323	5	8	1	5	f	f	WorkflowTransition	\N	\N
324	5	8	1	1	f	f	WorkflowTransition	\N	\N
325	5	8	2	3	f	f	WorkflowTransition	\N	\N
326	5	8	2	4	f	f	WorkflowTransition	\N	\N
327	5	8	2	5	f	f	WorkflowTransition	\N	\N
328	5	8	2	1	f	f	WorkflowTransition	\N	\N
329	5	8	3	3	f	f	WorkflowTransition	\N	\N
330	5	8	3	4	f	f	WorkflowTransition	\N	\N
331	5	8	3	5	f	f	WorkflowTransition	\N	\N
332	5	8	3	1	f	f	WorkflowTransition	\N	\N
333	5	8	5	3	f	f	WorkflowTransition	\N	\N
334	5	8	5	4	f	f	WorkflowTransition	\N	\N
335	5	8	5	5	f	f	WorkflowTransition	\N	\N
336	5	8	5	1	f	f	WorkflowTransition	\N	\N
337	5	8	6	3	f	f	WorkflowTransition	\N	\N
338	5	8	6	4	f	f	WorkflowTransition	\N	\N
339	5	8	6	5	f	f	WorkflowTransition	\N	\N
340	5	8	6	1	f	f	WorkflowTransition	\N	\N
341	5	8	7	3	f	f	WorkflowTransition	\N	\N
342	5	8	7	4	f	f	WorkflowTransition	\N	\N
343	5	8	7	5	f	f	WorkflowTransition	\N	\N
344	5	8	7	1	f	f	WorkflowTransition	\N	\N
345	4	1	7	3	f	f	WorkflowTransition	\N	\N
346	4	2	7	3	f	f	WorkflowTransition	\N	\N
347	4	3	7	3	f	f	WorkflowTransition	\N	\N
348	6	1	2	3	f	f	WorkflowTransition	\N	\N
349	6	1	3	3	f	f	WorkflowTransition	\N	\N
350	6	1	5	3	f	f	WorkflowTransition	\N	\N
351	6	1	6	3	f	f	WorkflowTransition	\N	\N
352	6	1	7	3	f	f	WorkflowTransition	\N	\N
353	6	2	1	3	f	f	WorkflowTransition	\N	\N
354	6	2	3	3	f	f	WorkflowTransition	\N	\N
355	6	2	5	3	f	f	WorkflowTransition	\N	\N
356	6	2	6	3	f	f	WorkflowTransition	\N	\N
357	6	2	7	3	f	f	WorkflowTransition	\N	\N
358	6	3	5	3	f	f	WorkflowTransition	\N	\N
359	6	3	6	3	f	f	WorkflowTransition	\N	\N
360	6	3	8	3	f	f	WorkflowTransition	\N	\N
361	6	5	1	3	f	f	WorkflowTransition	\N	\N
362	6	6	1	3	f	f	WorkflowTransition	\N	\N
363	6	8	1	3	f	f	WorkflowTransition	\N	\N
364	6	8	2	3	f	f	WorkflowTransition	\N	\N
365	6	8	3	3	f	f	WorkflowTransition	\N	\N
366	6	8	5	3	f	f	WorkflowTransition	\N	\N
367	6	8	6	3	f	f	WorkflowTransition	\N	\N
368	6	8	7	3	f	f	WorkflowTransition	\N	\N
369	6	3	7	3	f	f	WorkflowTransition	\N	\N
370	6	5	7	3	f	f	WorkflowTransition	\N	\N
371	6	6	7	3	f	f	WorkflowTransition	\N	\N
372	6	7	2	3	f	f	WorkflowTransition	\N	\N
373	6	7	3	3	f	f	WorkflowTransition	\N	\N
374	6	7	5	3	f	f	WorkflowTransition	\N	\N
375	6	7	6	3	f	f	WorkflowTransition	\N	\N
388	4	1	9	3	f	f	WorkflowTransition	\N	\N
389	4	1	9	4	f	f	WorkflowTransition	\N	\N
390	4	1	9	5	f	f	WorkflowTransition	\N	\N
391	4	1	9	1	f	f	WorkflowTransition	\N	\N
392	5	1	9	3	f	f	WorkflowTransition	\N	\N
393	5	1	9	4	f	f	WorkflowTransition	\N	\N
394	5	1	9	5	f	f	WorkflowTransition	\N	\N
395	5	1	9	1	f	f	WorkflowTransition	\N	\N
396	6	1	9	3	f	f	WorkflowTransition	\N	\N
397	6	1	9	4	f	f	WorkflowTransition	\N	\N
398	6	1	9	5	f	f	WorkflowTransition	\N	\N
399	6	1	9	1	f	f	WorkflowTransition	\N	\N
400	4	2	9	3	f	f	WorkflowTransition	\N	\N
401	4	2	9	4	f	f	WorkflowTransition	\N	\N
402	4	2	9	5	f	f	WorkflowTransition	\N	\N
403	4	2	9	1	f	f	WorkflowTransition	\N	\N
404	5	2	9	3	f	f	WorkflowTransition	\N	\N
405	5	2	9	4	f	f	WorkflowTransition	\N	\N
406	5	2	9	5	f	f	WorkflowTransition	\N	\N
407	5	2	9	1	f	f	WorkflowTransition	\N	\N
408	6	2	9	3	f	f	WorkflowTransition	\N	\N
409	6	2	9	4	f	f	WorkflowTransition	\N	\N
410	6	2	9	5	f	f	WorkflowTransition	\N	\N
411	6	2	9	1	f	f	WorkflowTransition	\N	\N
412	4	3	9	3	f	f	WorkflowTransition	\N	\N
413	4	3	9	4	f	f	WorkflowTransition	\N	\N
414	4	3	9	5	f	f	WorkflowTransition	\N	\N
415	4	3	9	1	f	f	WorkflowTransition	\N	\N
416	5	3	9	3	f	f	WorkflowTransition	\N	\N
417	5	3	9	4	f	f	WorkflowTransition	\N	\N
418	5	3	9	5	f	f	WorkflowTransition	\N	\N
419	5	3	9	1	f	f	WorkflowTransition	\N	\N
420	6	3	9	3	f	f	WorkflowTransition	\N	\N
421	6	3	9	4	f	f	WorkflowTransition	\N	\N
422	6	3	9	5	f	f	WorkflowTransition	\N	\N
423	6	3	9	1	f	f	WorkflowTransition	\N	\N
424	4	4	9	3	f	f	WorkflowTransition	\N	\N
425	4	4	9	4	f	f	WorkflowTransition	\N	\N
426	4	4	9	5	f	f	WorkflowTransition	\N	\N
427	4	4	9	1	f	f	WorkflowTransition	\N	\N
428	5	4	9	3	f	f	WorkflowTransition	\N	\N
429	5	4	9	4	f	f	WorkflowTransition	\N	\N
430	5	4	9	5	f	f	WorkflowTransition	\N	\N
431	5	4	9	1	f	f	WorkflowTransition	\N	\N
432	6	4	9	3	f	f	WorkflowTransition	\N	\N
433	6	4	9	4	f	f	WorkflowTransition	\N	\N
434	6	4	9	5	f	f	WorkflowTransition	\N	\N
435	6	4	9	1	f	f	WorkflowTransition	\N	\N
436	4	5	9	3	f	f	WorkflowTransition	\N	\N
437	4	5	9	4	f	f	WorkflowTransition	\N	\N
438	4	5	9	5	f	f	WorkflowTransition	\N	\N
439	4	5	9	1	f	f	WorkflowTransition	\N	\N
440	5	5	9	3	f	f	WorkflowTransition	\N	\N
441	5	5	9	4	f	f	WorkflowTransition	\N	\N
442	5	5	9	5	f	f	WorkflowTransition	\N	\N
443	5	5	9	1	f	f	WorkflowTransition	\N	\N
444	6	5	9	3	f	f	WorkflowTransition	\N	\N
445	6	5	9	4	f	f	WorkflowTransition	\N	\N
446	6	5	9	5	f	f	WorkflowTransition	\N	\N
447	6	5	9	1	f	f	WorkflowTransition	\N	\N
448	4	6	9	3	f	f	WorkflowTransition	\N	\N
449	4	6	9	4	f	f	WorkflowTransition	\N	\N
450	4	6	9	5	f	f	WorkflowTransition	\N	\N
451	4	6	9	1	f	f	WorkflowTransition	\N	\N
452	5	6	9	3	f	f	WorkflowTransition	\N	\N
453	5	6	9	4	f	f	WorkflowTransition	\N	\N
454	5	6	9	5	f	f	WorkflowTransition	\N	\N
455	5	6	9	1	f	f	WorkflowTransition	\N	\N
456	6	6	9	3	f	f	WorkflowTransition	\N	\N
457	6	6	9	4	f	f	WorkflowTransition	\N	\N
458	6	6	9	5	f	f	WorkflowTransition	\N	\N
459	6	6	9	1	f	f	WorkflowTransition	\N	\N
460	4	7	9	3	f	f	WorkflowTransition	\N	\N
461	4	7	9	4	f	f	WorkflowTransition	\N	\N
462	4	7	9	5	f	f	WorkflowTransition	\N	\N
463	4	7	9	1	f	f	WorkflowTransition	\N	\N
464	5	7	9	3	f	f	WorkflowTransition	\N	\N
465	5	7	9	4	f	f	WorkflowTransition	\N	\N
466	5	7	9	5	f	f	WorkflowTransition	\N	\N
467	5	7	9	1	f	f	WorkflowTransition	\N	\N
468	6	7	9	3	f	f	WorkflowTransition	\N	\N
469	6	7	9	4	f	f	WorkflowTransition	\N	\N
470	6	7	9	5	f	f	WorkflowTransition	\N	\N
471	6	7	9	1	f	f	WorkflowTransition	\N	\N
472	4	8	9	3	f	f	WorkflowTransition	\N	\N
473	4	8	9	4	f	f	WorkflowTransition	\N	\N
474	4	8	9	5	f	f	WorkflowTransition	\N	\N
475	4	8	9	1	f	f	WorkflowTransition	\N	\N
476	5	8	9	3	f	f	WorkflowTransition	\N	\N
477	5	8	9	4	f	f	WorkflowTransition	\N	\N
478	5	8	9	5	f	f	WorkflowTransition	\N	\N
479	5	8	9	1	f	f	WorkflowTransition	\N	\N
480	6	8	9	3	f	f	WorkflowTransition	\N	\N
481	6	8	9	4	f	f	WorkflowTransition	\N	\N
482	6	8	9	5	f	f	WorkflowTransition	\N	\N
483	6	8	9	1	f	f	WorkflowTransition	\N	\N
\.


--
-- Name: attachments_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.attachments_id_seq', 1, false);


--
-- Name: auth_sources_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.auth_sources_id_seq', 1, false);


--
-- Name: boards_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.boards_id_seq', 1, false);


--
-- Name: changes_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.changes_id_seq', 1, false);


--
-- Name: changesets_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.changesets_id_seq', 1, false);


--
-- Name: comments_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.comments_id_seq', 1, false);


--
-- Name: custom_field_enumerations_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.custom_field_enumerations_id_seq', 1, false);


--
-- Name: custom_fields_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.custom_fields_id_seq', 21, true);


--
-- Name: custom_values_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.custom_values_id_seq', 444, true);


--
-- Name: documents_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.documents_id_seq', 1, false);


--
-- Name: email_addresses_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.email_addresses_id_seq', 1, true);


--
-- Name: enabled_modules_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.enabled_modules_id_seq', 20, true);


--
-- Name: enumerations_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.enumerations_id_seq', 12, true);


--
-- Name: import_items_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.import_items_id_seq', 1, false);


--
-- Name: imports_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.imports_id_seq', 1, false);


--
-- Name: issue_categories_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.issue_categories_id_seq', 1, false);


--
-- Name: issue_relations_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.issue_relations_id_seq', 1, false);


--
-- Name: issue_statuses_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.issue_statuses_id_seq', 9, true);


--
-- Name: issues_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.issues_id_seq', 19, true);


--
-- Name: journal_details_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.journal_details_id_seq', 21, true);


--
-- Name: journals_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.journals_id_seq', 21, true);


--
-- Name: member_roles_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.member_roles_id_seq', 1, false);


--
-- Name: members_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.members_id_seq', 1, false);


--
-- Name: messages_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.messages_id_seq', 1, false);


--
-- Name: news_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.news_id_seq', 1, false);


--
-- Name: open_id_authentication_associations_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.open_id_authentication_associations_id_seq', 1, false);


--
-- Name: open_id_authentication_nonces_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.open_id_authentication_nonces_id_seq', 1, false);


--
-- Name: projects_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.projects_id_seq', 1, true);


--
-- Name: queries_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.queries_id_seq', 1, false);


--
-- Name: repositories_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.repositories_id_seq', 1, false);


--
-- Name: roles_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.roles_id_seq', 5, true);


--
-- Name: settings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.settings_id_seq', 2, true);


--
-- Name: time_entries_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.time_entries_id_seq', 1, false);


--
-- Name: tokens_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.tokens_id_seq', 12, true);


--
-- Name: trackers_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.trackers_id_seq', 6, true);


--
-- Name: user_preferences_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.user_preferences_id_seq', 1, true);


--
-- Name: users_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.users_id_seq', 4, true);


--
-- Name: versions_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.versions_id_seq', 1, false);


--
-- Name: watchers_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.watchers_id_seq', 25, true);


--
-- Name: wiki_content_versions_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.wiki_content_versions_id_seq', 1, false);


--
-- Name: wiki_contents_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.wiki_contents_id_seq', 1, false);


--
-- Name: wiki_pages_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.wiki_pages_id_seq', 1, false);


--
-- Name: wiki_redirects_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.wiki_redirects_id_seq', 1, false);


--
-- Name: wikis_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.wikis_id_seq', 2, true);


--
-- Name: workflows_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.workflows_id_seq', 555, true);


--
-- Name: ar_internal_metadata ar_internal_metadata_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.ar_internal_metadata
    ADD CONSTRAINT ar_internal_metadata_pkey PRIMARY KEY (key);


--
-- Name: attachments attachments_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.attachments
    ADD CONSTRAINT attachments_pkey PRIMARY KEY (id);


--
-- Name: auth_sources auth_sources_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.auth_sources
    ADD CONSTRAINT auth_sources_pkey PRIMARY KEY (id);


--
-- Name: boards boards_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.boards
    ADD CONSTRAINT boards_pkey PRIMARY KEY (id);


--
-- Name: changes changes_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.changes
    ADD CONSTRAINT changes_pkey PRIMARY KEY (id);


--
-- Name: changesets changesets_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.changesets
    ADD CONSTRAINT changesets_pkey PRIMARY KEY (id);


--
-- Name: comments comments_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.comments
    ADD CONSTRAINT comments_pkey PRIMARY KEY (id);


--
-- Name: custom_field_enumerations custom_field_enumerations_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.custom_field_enumerations
    ADD CONSTRAINT custom_field_enumerations_pkey PRIMARY KEY (id);


--
-- Name: custom_fields custom_fields_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.custom_fields
    ADD CONSTRAINT custom_fields_pkey PRIMARY KEY (id);


--
-- Name: custom_values custom_values_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.custom_values
    ADD CONSTRAINT custom_values_pkey PRIMARY KEY (id);


--
-- Name: documents documents_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.documents
    ADD CONSTRAINT documents_pkey PRIMARY KEY (id);


--
-- Name: email_addresses email_addresses_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.email_addresses
    ADD CONSTRAINT email_addresses_pkey PRIMARY KEY (id);


--
-- Name: enabled_modules enabled_modules_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.enabled_modules
    ADD CONSTRAINT enabled_modules_pkey PRIMARY KEY (id);


--
-- Name: enumerations enumerations_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.enumerations
    ADD CONSTRAINT enumerations_pkey PRIMARY KEY (id);


--
-- Name: import_items import_items_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.import_items
    ADD CONSTRAINT import_items_pkey PRIMARY KEY (id);


--
-- Name: imports imports_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.imports
    ADD CONSTRAINT imports_pkey PRIMARY KEY (id);


--
-- Name: issue_categories issue_categories_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.issue_categories
    ADD CONSTRAINT issue_categories_pkey PRIMARY KEY (id);


--
-- Name: issue_relations issue_relations_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.issue_relations
    ADD CONSTRAINT issue_relations_pkey PRIMARY KEY (id);


--
-- Name: issue_statuses issue_statuses_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.issue_statuses
    ADD CONSTRAINT issue_statuses_pkey PRIMARY KEY (id);


--
-- Name: issues issues_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.issues
    ADD CONSTRAINT issues_pkey PRIMARY KEY (id);


--
-- Name: journal_details journal_details_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.journal_details
    ADD CONSTRAINT journal_details_pkey PRIMARY KEY (id);


--
-- Name: journals journals_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.journals
    ADD CONSTRAINT journals_pkey PRIMARY KEY (id);


--
-- Name: member_roles member_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.member_roles
    ADD CONSTRAINT member_roles_pkey PRIMARY KEY (id);


--
-- Name: members members_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.members
    ADD CONSTRAINT members_pkey PRIMARY KEY (id);


--
-- Name: messages messages_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_pkey PRIMARY KEY (id);


--
-- Name: news news_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.news
    ADD CONSTRAINT news_pkey PRIMARY KEY (id);


--
-- Name: open_id_authentication_associations open_id_authentication_associations_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.open_id_authentication_associations
    ADD CONSTRAINT open_id_authentication_associations_pkey PRIMARY KEY (id);


--
-- Name: open_id_authentication_nonces open_id_authentication_nonces_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.open_id_authentication_nonces
    ADD CONSTRAINT open_id_authentication_nonces_pkey PRIMARY KEY (id);


--
-- Name: projects projects_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.projects
    ADD CONSTRAINT projects_pkey PRIMARY KEY (id);


--
-- Name: queries queries_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.queries
    ADD CONSTRAINT queries_pkey PRIMARY KEY (id);


--
-- Name: repositories repositories_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.repositories
    ADD CONSTRAINT repositories_pkey PRIMARY KEY (id);


--
-- Name: roles roles_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_pkey PRIMARY KEY (id);


--
-- Name: schema_migrations schema_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (version);


--
-- Name: settings settings_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.settings
    ADD CONSTRAINT settings_pkey PRIMARY KEY (id);


--
-- Name: time_entries time_entries_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.time_entries
    ADD CONSTRAINT time_entries_pkey PRIMARY KEY (id);


--
-- Name: tokens tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.tokens
    ADD CONSTRAINT tokens_pkey PRIMARY KEY (id);


--
-- Name: trackers trackers_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.trackers
    ADD CONSTRAINT trackers_pkey PRIMARY KEY (id);


--
-- Name: user_preferences user_preferences_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.user_preferences
    ADD CONSTRAINT user_preferences_pkey PRIMARY KEY (id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: versions versions_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.versions
    ADD CONSTRAINT versions_pkey PRIMARY KEY (id);


--
-- Name: watchers watchers_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.watchers
    ADD CONSTRAINT watchers_pkey PRIMARY KEY (id);


--
-- Name: wiki_content_versions wiki_content_versions_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.wiki_content_versions
    ADD CONSTRAINT wiki_content_versions_pkey PRIMARY KEY (id);


--
-- Name: wiki_contents wiki_contents_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.wiki_contents
    ADD CONSTRAINT wiki_contents_pkey PRIMARY KEY (id);


--
-- Name: wiki_pages wiki_pages_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.wiki_pages
    ADD CONSTRAINT wiki_pages_pkey PRIMARY KEY (id);


--
-- Name: wiki_redirects wiki_redirects_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.wiki_redirects
    ADD CONSTRAINT wiki_redirects_pkey PRIMARY KEY (id);


--
-- Name: wikis wikis_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.wikis
    ADD CONSTRAINT wikis_pkey PRIMARY KEY (id);


--
-- Name: workflows workflows_pkey; Type: CONSTRAINT; Schema: public; Owner: redmine
--

ALTER TABLE ONLY public.workflows
    ADD CONSTRAINT workflows_pkey PRIMARY KEY (id);


--
-- Name: boards_project_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX boards_project_id ON public.boards USING btree (project_id);


--
-- Name: changeset_parents_changeset_ids; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX changeset_parents_changeset_ids ON public.changeset_parents USING btree (changeset_id);


--
-- Name: changeset_parents_parent_ids; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX changeset_parents_parent_ids ON public.changeset_parents USING btree (parent_id);


--
-- Name: changesets_changeset_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX changesets_changeset_id ON public.changes USING btree (changeset_id);


--
-- Name: changesets_issues_ids; Type: INDEX; Schema: public; Owner: redmine
--

CREATE UNIQUE INDEX changesets_issues_ids ON public.changesets_issues USING btree (changeset_id, issue_id);


--
-- Name: changesets_repos_rev; Type: INDEX; Schema: public; Owner: redmine
--

CREATE UNIQUE INDEX changesets_repos_rev ON public.changesets USING btree (repository_id, revision);


--
-- Name: changesets_repos_scmid; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX changesets_repos_scmid ON public.changesets USING btree (repository_id, scmid);


--
-- Name: custom_fields_roles_ids; Type: INDEX; Schema: public; Owner: redmine
--

CREATE UNIQUE INDEX custom_fields_roles_ids ON public.custom_fields_roles USING btree (custom_field_id, role_id);


--
-- Name: custom_values_customized; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX custom_values_customized ON public.custom_values USING btree (customized_type, customized_id);


--
-- Name: documents_project_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX documents_project_id ON public.documents USING btree (project_id);


--
-- Name: enabled_modules_project_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX enabled_modules_project_id ON public.enabled_modules USING btree (project_id);


--
-- Name: groups_users_ids; Type: INDEX; Schema: public; Owner: redmine
--

CREATE UNIQUE INDEX groups_users_ids ON public.groups_users USING btree (group_id, user_id);


--
-- Name: index_attachments_on_author_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_attachments_on_author_id ON public.attachments USING btree (author_id);


--
-- Name: index_attachments_on_container_id_and_container_type; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_attachments_on_container_id_and_container_type ON public.attachments USING btree (container_id, container_type);


--
-- Name: index_attachments_on_created_on; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_attachments_on_created_on ON public.attachments USING btree (created_on);


--
-- Name: index_attachments_on_disk_filename; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_attachments_on_disk_filename ON public.attachments USING btree (disk_filename);


--
-- Name: index_auth_sources_on_id_and_type; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_auth_sources_on_id_and_type ON public.auth_sources USING btree (id, type);


--
-- Name: index_boards_on_last_message_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_boards_on_last_message_id ON public.boards USING btree (last_message_id);


--
-- Name: index_changesets_issues_on_issue_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_changesets_issues_on_issue_id ON public.changesets_issues USING btree (issue_id);


--
-- Name: index_changesets_on_committed_on; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_changesets_on_committed_on ON public.changesets USING btree (committed_on);


--
-- Name: index_changesets_on_repository_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_changesets_on_repository_id ON public.changesets USING btree (repository_id);


--
-- Name: index_changesets_on_user_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_changesets_on_user_id ON public.changesets USING btree (user_id);


--
-- Name: index_comments_on_author_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_comments_on_author_id ON public.comments USING btree (author_id);


--
-- Name: index_comments_on_commented_id_and_commented_type; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_comments_on_commented_id_and_commented_type ON public.comments USING btree (commented_id, commented_type);


--
-- Name: index_custom_fields_on_id_and_type; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_custom_fields_on_id_and_type ON public.custom_fields USING btree (id, type);


--
-- Name: index_custom_fields_projects_on_custom_field_id_and_project_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE UNIQUE INDEX index_custom_fields_projects_on_custom_field_id_and_project_id ON public.custom_fields_projects USING btree (custom_field_id, project_id);


--
-- Name: index_custom_fields_trackers_on_custom_field_id_and_tracker_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE UNIQUE INDEX index_custom_fields_trackers_on_custom_field_id_and_tracker_id ON public.custom_fields_trackers USING btree (custom_field_id, tracker_id);


--
-- Name: index_custom_values_on_custom_field_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_custom_values_on_custom_field_id ON public.custom_values USING btree (custom_field_id);


--
-- Name: index_documents_on_category_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_documents_on_category_id ON public.documents USING btree (category_id);


--
-- Name: index_documents_on_created_on; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_documents_on_created_on ON public.documents USING btree (created_on);


--
-- Name: index_email_addresses_on_user_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_email_addresses_on_user_id ON public.email_addresses USING btree (user_id);


--
-- Name: index_enumerations_on_id_and_type; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_enumerations_on_id_and_type ON public.enumerations USING btree (id, type);


--
-- Name: index_enumerations_on_project_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_enumerations_on_project_id ON public.enumerations USING btree (project_id);


--
-- Name: index_import_items_on_import_id_and_unique_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_import_items_on_import_id_and_unique_id ON public.import_items USING btree (import_id, unique_id);


--
-- Name: index_issue_categories_on_assigned_to_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_issue_categories_on_assigned_to_id ON public.issue_categories USING btree (assigned_to_id);


--
-- Name: index_issue_relations_on_issue_from_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_issue_relations_on_issue_from_id ON public.issue_relations USING btree (issue_from_id);


--
-- Name: index_issue_relations_on_issue_from_id_and_issue_to_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE UNIQUE INDEX index_issue_relations_on_issue_from_id_and_issue_to_id ON public.issue_relations USING btree (issue_from_id, issue_to_id);


--
-- Name: index_issue_relations_on_issue_to_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_issue_relations_on_issue_to_id ON public.issue_relations USING btree (issue_to_id);


--
-- Name: index_issue_statuses_on_is_closed; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_issue_statuses_on_is_closed ON public.issue_statuses USING btree (is_closed);


--
-- Name: index_issue_statuses_on_position; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_issue_statuses_on_position ON public.issue_statuses USING btree ("position");


--
-- Name: index_issues_on_assigned_to_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_issues_on_assigned_to_id ON public.issues USING btree (assigned_to_id);


--
-- Name: index_issues_on_author_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_issues_on_author_id ON public.issues USING btree (author_id);


--
-- Name: index_issues_on_category_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_issues_on_category_id ON public.issues USING btree (category_id);


--
-- Name: index_issues_on_created_on; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_issues_on_created_on ON public.issues USING btree (created_on);


--
-- Name: index_issues_on_fixed_version_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_issues_on_fixed_version_id ON public.issues USING btree (fixed_version_id);


--
-- Name: index_issues_on_parent_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_issues_on_parent_id ON public.issues USING btree (parent_id);


--
-- Name: index_issues_on_priority_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_issues_on_priority_id ON public.issues USING btree (priority_id);


--
-- Name: index_issues_on_root_id_and_lft_and_rgt; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_issues_on_root_id_and_lft_and_rgt ON public.issues USING btree (root_id, lft, rgt);


--
-- Name: index_issues_on_status_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_issues_on_status_id ON public.issues USING btree (status_id);


--
-- Name: index_issues_on_tracker_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_issues_on_tracker_id ON public.issues USING btree (tracker_id);


--
-- Name: index_journals_on_created_on; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_journals_on_created_on ON public.journals USING btree (created_on);


--
-- Name: index_journals_on_journalized_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_journals_on_journalized_id ON public.journals USING btree (journalized_id);


--
-- Name: index_journals_on_user_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_journals_on_user_id ON public.journals USING btree (user_id);


--
-- Name: index_member_roles_on_inherited_from; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_member_roles_on_inherited_from ON public.member_roles USING btree (inherited_from);


--
-- Name: index_member_roles_on_member_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_member_roles_on_member_id ON public.member_roles USING btree (member_id);


--
-- Name: index_member_roles_on_role_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_member_roles_on_role_id ON public.member_roles USING btree (role_id);


--
-- Name: index_members_on_project_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_members_on_project_id ON public.members USING btree (project_id);


--
-- Name: index_members_on_user_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_members_on_user_id ON public.members USING btree (user_id);


--
-- Name: index_members_on_user_id_and_project_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE UNIQUE INDEX index_members_on_user_id_and_project_id ON public.members USING btree (user_id, project_id);


--
-- Name: index_messages_on_author_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_messages_on_author_id ON public.messages USING btree (author_id);


--
-- Name: index_messages_on_created_on; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_messages_on_created_on ON public.messages USING btree (created_on);


--
-- Name: index_messages_on_last_reply_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_messages_on_last_reply_id ON public.messages USING btree (last_reply_id);


--
-- Name: index_news_on_author_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_news_on_author_id ON public.news USING btree (author_id);


--
-- Name: index_news_on_created_on; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_news_on_created_on ON public.news USING btree (created_on);


--
-- Name: index_projects_on_lft; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_projects_on_lft ON public.projects USING btree (lft);


--
-- Name: index_projects_on_rgt; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_projects_on_rgt ON public.projects USING btree (rgt);


--
-- Name: index_queries_on_project_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_queries_on_project_id ON public.queries USING btree (project_id);


--
-- Name: index_queries_on_user_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_queries_on_user_id ON public.queries USING btree (user_id);


--
-- Name: index_repositories_on_project_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_repositories_on_project_id ON public.repositories USING btree (project_id);


--
-- Name: index_roles_managed_roles_on_role_id_and_managed_role_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE UNIQUE INDEX index_roles_managed_roles_on_role_id_and_managed_role_id ON public.roles_managed_roles USING btree (role_id, managed_role_id);


--
-- Name: index_settings_on_name; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_settings_on_name ON public.settings USING btree (name);


--
-- Name: index_time_entries_on_activity_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_time_entries_on_activity_id ON public.time_entries USING btree (activity_id);


--
-- Name: index_time_entries_on_created_on; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_time_entries_on_created_on ON public.time_entries USING btree (created_on);


--
-- Name: index_time_entries_on_user_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_time_entries_on_user_id ON public.time_entries USING btree (user_id);


--
-- Name: index_tokens_on_user_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_tokens_on_user_id ON public.tokens USING btree (user_id);


--
-- Name: index_user_preferences_on_user_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_user_preferences_on_user_id ON public.user_preferences USING btree (user_id);


--
-- Name: index_users_on_auth_source_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_users_on_auth_source_id ON public.users USING btree (auth_source_id);


--
-- Name: index_users_on_id_and_type; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_users_on_id_and_type ON public.users USING btree (id, type);


--
-- Name: index_users_on_type; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_users_on_type ON public.users USING btree (type);


--
-- Name: index_versions_on_sharing; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_versions_on_sharing ON public.versions USING btree (sharing);


--
-- Name: index_watchers_on_user_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_watchers_on_user_id ON public.watchers USING btree (user_id);


--
-- Name: index_watchers_on_watchable_id_and_watchable_type; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_watchers_on_watchable_id_and_watchable_type ON public.watchers USING btree (watchable_id, watchable_type);


--
-- Name: index_wiki_content_versions_on_updated_on; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_wiki_content_versions_on_updated_on ON public.wiki_content_versions USING btree (updated_on);


--
-- Name: index_wiki_contents_on_author_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_wiki_contents_on_author_id ON public.wiki_contents USING btree (author_id);


--
-- Name: index_wiki_pages_on_parent_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_wiki_pages_on_parent_id ON public.wiki_pages USING btree (parent_id);


--
-- Name: index_wiki_pages_on_wiki_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_wiki_pages_on_wiki_id ON public.wiki_pages USING btree (wiki_id);


--
-- Name: index_wiki_redirects_on_wiki_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_wiki_redirects_on_wiki_id ON public.wiki_redirects USING btree (wiki_id);


--
-- Name: index_workflows_on_new_status_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_workflows_on_new_status_id ON public.workflows USING btree (new_status_id);


--
-- Name: index_workflows_on_old_status_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_workflows_on_old_status_id ON public.workflows USING btree (old_status_id);


--
-- Name: index_workflows_on_role_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_workflows_on_role_id ON public.workflows USING btree (role_id);


--
-- Name: index_workflows_on_tracker_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX index_workflows_on_tracker_id ON public.workflows USING btree (tracker_id);


--
-- Name: issue_categories_project_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX issue_categories_project_id ON public.issue_categories USING btree (project_id);


--
-- Name: issues_project_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX issues_project_id ON public.issues USING btree (project_id);


--
-- Name: journal_details_journal_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX journal_details_journal_id ON public.journal_details USING btree (journal_id);


--
-- Name: journals_journalized_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX journals_journalized_id ON public.journals USING btree (journalized_id, journalized_type);


--
-- Name: messages_board_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX messages_board_id ON public.messages USING btree (board_id);


--
-- Name: messages_parent_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX messages_parent_id ON public.messages USING btree (parent_id);


--
-- Name: news_project_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX news_project_id ON public.news USING btree (project_id);


--
-- Name: projects_trackers_project_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX projects_trackers_project_id ON public.projects_trackers USING btree (project_id);


--
-- Name: projects_trackers_unique; Type: INDEX; Schema: public; Owner: redmine
--

CREATE UNIQUE INDEX projects_trackers_unique ON public.projects_trackers USING btree (project_id, tracker_id);


--
-- Name: queries_roles_ids; Type: INDEX; Schema: public; Owner: redmine
--

CREATE UNIQUE INDEX queries_roles_ids ON public.queries_roles USING btree (query_id, role_id);


--
-- Name: time_entries_issue_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX time_entries_issue_id ON public.time_entries USING btree (issue_id);


--
-- Name: time_entries_project_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX time_entries_project_id ON public.time_entries USING btree (project_id);


--
-- Name: tokens_value; Type: INDEX; Schema: public; Owner: redmine
--

CREATE UNIQUE INDEX tokens_value ON public.tokens USING btree (value);


--
-- Name: versions_project_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX versions_project_id ON public.versions USING btree (project_id);


--
-- Name: watchers_user_id_type; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX watchers_user_id_type ON public.watchers USING btree (user_id, watchable_type);


--
-- Name: wiki_content_versions_wcid; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX wiki_content_versions_wcid ON public.wiki_content_versions USING btree (wiki_content_id);


--
-- Name: wiki_contents_page_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX wiki_contents_page_id ON public.wiki_contents USING btree (page_id);


--
-- Name: wiki_pages_wiki_id_title; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX wiki_pages_wiki_id_title ON public.wiki_pages USING btree (wiki_id, title);


--
-- Name: wiki_redirects_wiki_id_title; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX wiki_redirects_wiki_id_title ON public.wiki_redirects USING btree (wiki_id, title);


--
-- Name: wikis_project_id; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX wikis_project_id ON public.wikis USING btree (project_id);


--
-- Name: wkfs_role_tracker_old_status; Type: INDEX; Schema: public; Owner: redmine
--

CREATE INDEX wkfs_role_tracker_old_status ON public.workflows USING btree (role_id, tracker_id, old_status_id);


--
-- PostgreSQL database dump complete
--

