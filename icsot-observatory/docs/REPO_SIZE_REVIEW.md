# Reported repository size and capture outcomes

Sizes retrieved 2026-10-26T16:35:55.404633+00:00 through 2026-10-26T16:36:04.823317+00:00. All 185 repositories returned a size; unknown/missing: 0. The final snapshot used three GraphQL requests, total query cost 3.

Terminal outcomes are 167 accepted and 18 incomplete, based on hash-validated evidence indexes and verifier/transfer metadata. Bundle and archive sizes are the existing captured artifacts, not new downloads.

**There is no observed size-only failure boundary.** A 5 GB automatic guardrail can reflect the user's conservative preference for future repositories. No current repository reaches even 2 GB by the reported metric, so this sample cannot calibrate a 5 GB failure cutoff.

## Accepted versus incomplete sizes

| Outcome | Repositories | Known sizes | Minimum reported KB | Median reported KB | Maximum reported KB | Verified Git bundle recorded |
|---|---:|---:|---:|---:|---:|---:|
| accepted | 167 | 167 | 474 | 37,986.0 | 1,914,819 | 167 |
| incomplete | 18 | 18 | 24,270 | 369,332.5 | 1,671,898 | 15 |

## Metric and thresholds

GitHub documents `Repository.diskUsage` in kilobytes. Here **1 nominal GB = 1,000,000 reported KB**. The raw metric is retained in the [185-row CSV](data/repo-size-outcomes-2026-10-26.csv). This is not a measurement of the full all-ref mirror, Git bundle, API archive, temporary restore space or runtime. [GitHub field documentation](https://docs.github.com/en/graphql/reference/repos).

| Threshold | Reported KB cutoff | Flagged | Accepted | Incomplete |
|---|---:|---:|---:|---:|
| 1 GB | 1,000,000 | 8 | 5 | 3 |
| 2 GB | 2,000,000 | 0 | 0 | 0 |
| 5 GB | 5,000,000 | 0 | 0 | 0 |

At 1 GB, five of eight flagged repositories were accepted. Seven of eight have verified portable Git bundles. Below 1 GB, 162 of 177 were accepted and 15 incomplete. The observed failure proportions are 37.5% versus 8.5%, but the larger group has only eight repositories and the recorded failures concern API behavior or an unresolved collection deadline. These descriptive counts do not establish a Git-size mechanism or clean cutoff.

## All repositories at least 1 GB

| Repository | Reported KB | Nominal GB | Outcome | Git bundle GB | Encrypted archive GB | Git status | Primary cause | Overlap |
|---|---|---|---|---|---|---|---|---|
| FirelyTeam/firely-net-sdk | 1,914,819 | 1.915 | accepted | 1.973 | 1.972 | verified bundle | none | none |
| aws/aws-lc | 1,780,870 | 1.781 | accepted | 3.060 | 3.057 | verified bundle | none | none |
| nodejs/node | 1,671,898 | 1.672 | incomplete | not recorded | 0.125 | no Git snapshot recorded | 7200 s collection deadline | none |
| v8/v8 | 1,252,782 | 1.253 | accepted | 1.291 | 1.188 | verified bundle | none | none |
| openemr/openemr | 1,179,770 | 1.180 | incomplete | 1.636 | 1.633 | verified bundle | review comments HTTP 502 | none |
| wolfSSL/wolfssl | 1,056,586 | 1.057 | incomplete | 1.183 | 1.146 | verified bundle | API reserve refusal | issue/PR/comment pagination drift |
| RT-Thread/rt-thread | 1,036,187 | 1.036 | accepted | 1.682 | 1.673 | verified bundle | none | none |
| hapifhir/hapi-fhir | 1,019,481 | 1.019 | accepted | 1.253 | 1.226 | verified bundle | none | none |

## Ten largest accepted repositories

| Repository | Reported KB | Nominal GB | Outcome | Git bundle GB | Encrypted archive GB | Git status |
|---|---|---|---|---|---|---|
| FirelyTeam/firely-net-sdk | 1,914,819 | 1.915 | accepted | 1.973 | 1.972 | verified bundle |
| aws/aws-lc | 1,780,870 | 1.781 | accepted | 3.060 | 3.057 | verified bundle |
| v8/v8 | 1,252,782 | 1.253 | accepted | 1.291 | 1.188 | verified bundle |
| RT-Thread/rt-thread | 1,036,187 | 1.036 | accepted | 1.682 | 1.673 | verified bundle |
| hapifhir/hapi-fhir | 1,019,481 | 1.019 | accepted | 1.253 | 1.226 | verified bundle |
| postgres/postgres | 804,698 | 0.805 | accepted | 0.935 | 0.913 | verified bundle |
| sqlite/sqlite | 581,683 | 0.582 | accepted | 0.599 | 0.595 | verified bundle |
| metriport/metriport | 550,847 | 0.551 | accepted | 0.569 | 0.588 | verified bundle |
| OHIF/Viewers | 535,314 | 0.535 | accepted | 1.122 | 1.104 | verified bundle |
| FFmpeg/FFmpeg | 504,378 | 0.504 | accepted | 0.553 | 0.528 | verified bundle |

## All 18 incomplete repositories

| Repository | Reported KB | Nominal GB | Outcome | Git bundle GB | Encrypted archive GB | Git status | Primary cause | Overlap |
|---|---|---|---|---|---|---|---|---|
| nodejs/node | 1,671,898 | 1.672 | incomplete | not recorded | 0.125 | no Git snapshot recorded | 7200 s collection deadline | none |
| openemr/openemr | 1,179,770 | 1.180 | incomplete | 1.636 | 1.633 | verified bundle | review comments HTTP 502 | none |
| wolfSSL/wolfssl | 1,056,586 | 1.057 | incomplete | 1.183 | 1.146 | verified bundle | API reserve refusal | issue/PR/comment pagination drift |
| zephyrproject-rtos/zephyr | 973,212 | 0.973 | incomplete | not recorded | 1.961 | mirror retained, unverified | API reserve refusal | Git ref churn |
| python/cpython | 903,328 | 0.903 | incomplete | 3.068 | 3.022 | verified bundle | API reserve refusal | none |
| php/php-src | 673,103 | 0.673 | incomplete | not recorded | 0.045 | no Git snapshot recorded | 7200 s collection deadline | none |
| keycloak/keycloak | 625,069 | 0.625 | incomplete | 0.923 | 0.934 | verified bundle | API reserve refusal | issue/PR/comment pagination drift |
| apache/nuttx | 394,375 | 0.394 | incomplete | 0.497 | 0.512 | verified bundle | API reserve refusal | none |
| openssl/openssl | 375,086 | 0.375 | incomplete | 0.638 | 0.655 | verified bundle | API reserve refusal | none |
| envoyproxy/envoy | 363,579 | 0.364 | incomplete | 2.044 | 2.030 | verified bundle | API reserve refusal | none |
| DIGI-UW/OpenELIS-Global-2 | 343,240 | 0.343 | incomplete | 0.542 | 0.536 | verified bundle | Events pagination drift | none |
| protocolbuffers/protobuf | 249,289 | 0.249 | incomplete | 0.341 | 0.360 | verified bundle | API reserve refusal | none |
| redis/redis | 219,387 | 0.219 | incomplete | 0.512 | 0.522 | verified bundle | API reserve refusal | none |
| RIOT-OS/RIOT | 187,959 | 0.188 | incomplete | 0.294 | 0.312 | verified bundle | API reserve refusal | none |
| eProsima/Fast-DDS | 149,703 | 0.150 | incomplete | 0.205 | 0.207 | verified bundle | Events pagination drift | none |
| emqx/emqx | 148,376 | 0.148 | incomplete | 0.170 | 0.188 | verified bundle | API reserve refusal | issue/PR/comment pagination drift |
| microsoft/fhir-server | 136,478 | 0.136 | incomplete | 0.174 | 0.180 | verified bundle | Events pagination drift | none |
| libjpeg-turbo/libjpeg-turbo | 24,270 | 0.024 | incomplete | 0.028 | 0.030 | verified bundle | Events pagination drift | none |

Primary causes remain 11 client API reserve refusals, four Events-only pagination failures, one upstream HTTP 502, and two collection deadlines. Overlaps comprise three other pagination failures and Zephyr Git-ref churn. The stale-reset bug was reproduced independently; individual live reserve refusals cannot be attributed without their retained headers.

## PHP and Node manual review

PHP reports 673,103 KB (0.673 nominal GB); Node reports 1,671,898 KB (1.672 nominal GB). Both exhausted the 7200-second combined collection phase. Neither records a manifest, verified Git bundle or retained Git mirror. The available metadata does not establish Git-size causality, an exact blocked stage, or the API/wait share. Treat them as explicit manual-review/override candidates, not automatic size labels.

## Recommendation

Use only reported size for automatic `LARGE_REPO` classification. If the chosen policy is 5 GB, encode its raw cutoff and unit explicitly: **5,000,000 reported KB** under this convention. It currently flags zero targets and is a conservative future guardrail, not an empirically optimal cutoff. Treat missing size as unknown, never zero. Keep manual overrides separate from deadline/quota/error causes.

For capacity planning, actual captures can be larger: aws-lc was accepted with a 3.060 GB portable Git bundle despite reporting 1.781 nominal GB. A threshold on reported size therefore cannot replace separate working-space measurements.

Full comparable inventory: [185-row CSV](data/repo-size-outcomes-2026-10-26.csv). No archives, keys, Docker or remote mutations were used.
