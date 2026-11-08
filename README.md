# SCA: 30 проектов, OSV-Scanner и Grype

**В этом репозитории нет заранее собранных результатов.** Это только исходный код автоматизации.

Нажмите **Actions → SCA - build archive for 30 projects → Run workflow** (ветка `main`).
GitHub Actions сам выполнит сканирование всех 30 проектов и создаст **ОДИН главный архив** `SCA-RESULTS-30-PROJECTS`.

После завершения откройте нужный запуск → **Artifacts** и скачайте `SCA-RESULTS-30-PROJECTS`. GitHub скачает ZIP, внутри которого находятся:

```text
INDEX.csv             # summary across all 30 applications
osv-test/
  osv.json             # original OSV-Scanner report
  grype.json           # original Grype report
  default.json         # provisional merged reference list
nodejs-goof/
  osv.json
  grype.json
  default.json
... (30 project folders total, each with EXACTLY THREE JSON files)

```

**Принцип формирования `default`:** объединение находок OSV и Grype с удалением повторов и сопоставлением CVE/GHSA. Отдельные записи из `ground-truth/verified.csv` дополнительно имеют пометку `project_and_advisory_verified`, если проверены по зафиксированным зависимостям проекта и независимому advisory. Все остальные имеют пометку `scanner_union_provisional` — это **не** независимый, гарантированно полный эталон. Уязвимости, пропущенные **обоими** инструментами, могут отсутствовать.

Это только SCA-анализ зависимостей. Уязвимости собственного кода (SAST) и секреты здесь не анализируются.

## Что лежит в репозитории до запуска

```text
.github/workflows/sca-scan.yml     # параллельные сканы 30 проектов и сборка одного архива
projects/manifest.json            # список и pinned SHA всех 30 upstream-репозиториев
ground-truth/verified.csv          # независимо проверенные эталонные строки, если есть
scripts/                            # обработка и проверка всех отчётов
tests/                              # тесты разборщиков и валидатора
```

Репозиторий остаётся чистым: **workflow не делает git commit/push и не создаёт папки `application/` в ветке**. Они появляются только во время запуска на GitHub runner и сохраняются в итоговом артефакте.

## Результаты при сбоях

When a scanner fails, its corresponding `osv.json` / `grype.json` contains a clear error status instead of fabricated empty findings; the merged `default.json` also records both scanner statuses. Internal diagnostics are available in temporary GitHub Actions artifacts, not in the final project folders.

При частичном сбое итоговый ZIP всё равно будет сформирован, но workflow сообщит об ошибке после загрузки артефакта, чтобы сбой не остался незамеченным.

## Воспроизводимость

OSV-Scanner v2.7.0 и Grype v0.121.2, исходные проекты по закреплённым SHA. Базы уязвимостей могут меняться между запусками, поэтому `default.json` contains the pinned commit and GitHub Actions run URL; scanner versions are fixed in the workflow.
