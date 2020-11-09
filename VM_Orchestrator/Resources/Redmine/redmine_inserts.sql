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
21	IssueCustomField	Branch	string	\N		\N	\N	t	t	f	20	f		t	t	f	--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: ''\nurl_pattern: ''\n	
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
\.


--
-- Data for Name: journal_details; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.journal_details (id, journal_id, property, prop_key, old_value, value) FROM stdin;
\.


--
-- Data for Name: journals; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.journals (id, journalized_id, journalized_type, user_id, notes, created_on, private_notes) FROM stdin;
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
\.


--
-- Data for Name: projects_trackers; Type: TABLE DATA; Schema: public; Owner: redmine
--

COPY public.projects_trackers (project_id, tracker_id) FROM stdin;
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
12	1	session	b5bc18d5690672cc7856f128f3ca462f6aa10569	2020-11-09 18:56:32.125262	2020-11-09 18:58:35.221612
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
1	admin	c28dd339002ef77f41f906b37c981a6092e96df3	Redmine	Admin	t	1	2020-11-09 18:56:32.108929		\N	2020-09-04 16:38:05.505611	2020-09-04 16:40:19.852077	User	\N	all	e0aecc28f14936ad507b533cdd772a87	f	2020-09-04 16:40:19
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
556	6	1	2	4	f	f	WorkflowTransition	\N	\N
557	6	1	2	5	f	f	WorkflowTransition	\N	\N
558	6	1	2	1	f	f	WorkflowTransition	\N	\N
559	6	1	3	4	f	f	WorkflowTransition	\N	\N
560	6	1	3	5	f	f	WorkflowTransition	\N	\N
561	6	1	3	1	f	f	WorkflowTransition	\N	\N
562	6	1	4	3	f	f	WorkflowTransition	\N	\N
563	6	1	4	4	f	f	WorkflowTransition	\N	\N
564	6	1	4	5	f	f	WorkflowTransition	\N	\N
565	6	1	4	1	f	f	WorkflowTransition	\N	\N
566	6	1	5	4	f	f	WorkflowTransition	\N	\N
567	6	1	5	5	f	f	WorkflowTransition	\N	\N
568	6	1	5	1	f	f	WorkflowTransition	\N	\N
569	6	1	6	4	f	f	WorkflowTransition	\N	\N
570	6	1	6	5	f	f	WorkflowTransition	\N	\N
571	6	1	6	1	f	f	WorkflowTransition	\N	\N
572	6	1	7	4	f	f	WorkflowTransition	\N	\N
573	6	1	7	5	f	f	WorkflowTransition	\N	\N
574	6	1	7	1	f	f	WorkflowTransition	\N	\N
575	6	1	8	3	f	f	WorkflowTransition	\N	\N
576	6	1	8	4	f	f	WorkflowTransition	\N	\N
577	6	1	8	5	f	f	WorkflowTransition	\N	\N
578	6	1	8	1	f	f	WorkflowTransition	\N	\N
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

SELECT pg_catalog.setval('public.custom_values_id_seq', 102, true);


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

SELECT pg_catalog.setval('public.enabled_modules_id_seq', 10, true);


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

SELECT pg_catalog.setval('public.issues_id_seq', 1, false);


--
-- Name: journal_details_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.journal_details_id_seq', 2, true);


--
-- Name: journals_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.journals_id_seq', 2, true);


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

SELECT pg_catalog.setval('public.projects_id_seq', 1, false);


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

SELECT pg_catalog.setval('public.watchers_id_seq', 6, true);


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

SELECT pg_catalog.setval('public.wikis_id_seq', 1, true);


--
-- Name: workflows_id_seq; Type: SEQUENCE SET; Schema: public; Owner: redmine
--

SELECT pg_catalog.setval('public.workflows_id_seq', 578, true);


--
-- PostgreSQL database dump complete
--

