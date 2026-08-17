CREATE TABLE IF NOT EXISTS "victims" (
    "id" TEXT NOT NULL,
    "hostname" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "code" TEXT NOT NULL,
    "upload_time" BIGINT NOT NULL,
    "complete" BOOLEAN NOT NULL,
    PRIMARY KEY ("id")
);