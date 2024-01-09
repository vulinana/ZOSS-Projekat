/*
  Warnings:

  - You are about to drop the `User` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropTable
DROP TABLE "User";

-- CreateTable
CREATE TABLE "Korisnik" (
    "id" SERIAL NOT NULL,
    "korisnickoIme" TEXT NOT NULL,
    "sifra" TEXT,

    CONSTRAINT "Korisnik_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Korisnik_korisnickoIme_key" ON "Korisnik"("korisnickoIme");
