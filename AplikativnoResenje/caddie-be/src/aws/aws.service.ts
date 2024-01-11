import { Injectable, NotFoundException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { S3 } from 'aws-sdk';
import * as crypto from 'crypto';

@Injectable()
export class AwsService {
    constructor(private configService: ConfigService) {}

    bucketName = this.configService.get('AWS_BUCKET_NAME')
    s3 = new S3({
        accessKeyId: this.configService.get('ACCESS_KEY'),
        secretAccessKey: this.configService.get('AWS_SECRET_KEY')
    })

    async uploadPublicFile(dataBuffer: Buffer, filename: string) {
        try {
            const uploadResult = await this.s3
            .upload({
                Bucket: this.bucketName,
                Body: dataBuffer,
                Key: filename,
                ContentDisposition: 'inline',
                //ServerSideEncryption: 'AES256',
                //ACL: 'public-read'
            })
            .promise()

            return uploadResult
        } catch(error) {
            console.log(error)
        }
    }

    async getFiles() {
        try {
            const params = {
                Bucket: this.bucketName,
            };

            const data = await this.s3.listObjectsV2(params).promise();
            return data.Contents;
        } catch (error) {
            console.error('Error listing files:', error);
            throw error;
        }
    }

    async getFileById(id: string) {
        try {
            const params = {
                Bucket: this.bucketName,
                Key: id,
            };

            const data = await this.s3.getObject(params).promise();
            return data.Body;
        } catch (error) {
            console.error(`Error fetching file with id ${id}:`, error);
            if (error.code === 'NoSuchKey') {
                throw new NotFoundException(`File with id ${id} not found`);
            }
            throw error;
        }
    }

    async uploadEncryptedFile(dataBuffer: Buffer, filename: string) {
        try {
            const encryptedData = this.encryptData(dataBuffer);

            const uploadResult = await this.s3
            .upload({
                Bucket: this.bucketName,
                Body: encryptedData,
                Key: filename,
                ContentDisposition: 'inline'
            })
            .promise()

            return uploadResult
        } catch(error) {
            console.log(error)
        }
    }

    async getDecryptedFileById(id: string) {
        try {
            const params = {
                Bucket: this.bucketName,
                Key: id,
            };

            const data = await this.s3.getObject(params).promise();
            const bodyBuffer = Buffer.from(data.Body as Uint8Array);
            const decryptedData = this.decryptData(bodyBuffer);
            return decryptedData;
        } catch (error) {
            console.error(`Error fetching or decrypting file with id ${id}:`, error);
            if (error.code === 'NoSuchKey') {
                throw new NotFoundException(`File with id ${id} not found`);
            }
            throw error;
        }
    }

    keyHex = this.configService.get('CRYPTO_KEY')
    ivHex = this.configService.get('CRYPTO_IV')
    algorithm = this.configService.get('CRYPTO_ALGORITHM')
    encryptData(dataBuffer: Buffer): Buffer {
        const key = Buffer.from(this.keyHex, 'hex')
        const iv = Buffer.from(this.ivHex, 'hex')
        const cipher = crypto.createCipheriv(this.algorithm, key, iv);
        const encryptedBuffer = Buffer.concat([cipher.update(dataBuffer), cipher.final()]);
        return Buffer.concat([key, iv, encryptedBuffer]);
    }

    decryptData(encryptedBuffer: Buffer): Buffer {
        const key = Buffer.from(this.keyHex, 'hex');
        const iv = Buffer.from(this.ivHex, 'hex');
        const receivedKey = encryptedBuffer.slice(0, 32);
        const receivedIV = encryptedBuffer.slice(32, 48);
        const receivedEncryptedBuffer = encryptedBuffer.slice(48);
    
        const decipher = crypto.createDecipheriv(this.algorithm, key, iv);
        const decryptedBuffer = Buffer.concat([decipher.update(receivedEncryptedBuffer), decipher.final()]);
        return decryptedBuffer;
    }


}