# -satoshi-watanabe-0001-ahamo-dummy-demo2-auth-service

Spring Boot 3.x authentication service with JWT token support for the ahamo dummy demo2 system.

## Features
- JWT token-based authentication (1-hour access tokens, 24-hour refresh tokens)
- BCrypt password hashing (strength 12)
- Rate limiting (5 failed attempts)
- PostgreSQL integration with Flyway migrations
- Comprehensive unit tests (80%+ coverage)
- Docker containerization support
# バックエンドE2E統合テスト - 認証修正後のテスト実行
# バックエンドE2Eワークフロー権限修正テスト

このPRはPR #9のworkflow_call権限修正が正常に動作するかテストするためのものです。

## 変更内容
- READMEにテスト用コメントを追加

## 期待される結果
- Backend E2E Integration Testingワークフローが正常に実行される
- リポジトリチェックアウトエラーが発生しない

