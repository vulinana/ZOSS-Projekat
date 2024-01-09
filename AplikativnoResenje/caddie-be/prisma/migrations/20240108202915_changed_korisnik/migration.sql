/*
  Warnings:

  - You are about to drop the column `korisnickoIme` on the `Korisnik` table. All the data in the column will be lost.
  - A unique constraint covering the columns `[korisnicko_ime]` on the table `Korisnik` will be added. If there are existing duplicate values, this will fail.
  - Added the required column `korisnicko_ime` to the `Korisnik` table without a default value. This is not possible if the table is not empty.
  - Made the column `sifra` on table `Korisnik` required. This step will fail if there are existing NULL values in that column.

*/
-- DropIndex
DROP INDEX "Korisnik_korisnickoIme_key";

-- AlterTable
ALTER TABLE "Korisnik" DROP COLUMN "korisnickoIme",
ADD COLUMN     "korisnicko_ime" TEXT NOT NULL,
ALTER COLUMN "sifra" SET NOT NULL;

-- CreateIndex
CREATE UNIQUE INDEX "Korisnik_korisnicko_ime_key" ON "Korisnik"("korisnicko_ime");
