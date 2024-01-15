import { Controller, Post, Get, Req, Res, UploadedFile, UseInterceptors, Param } from "@nestjs/common";
import { FileInterceptor } from "@nestjs/platform-express";
import { Express } from "express";
import { AwsService } from "./aws.service";

@Controller('aws')
export class AwsController {
    constructor (private readonly awsService: AwsService) {}

    @Post()
    @UseInterceptors(FileInterceptor('image'))
    async uploadFile(
        @UploadedFile() file: Express.Multer.File,
        @Req() request,
        @Res() response 
    ) {
        try {
            //const uploadResult = await this.awsService.uploadEncryptedFile(file.buffer, file.originalname);
            const uploadResult = await this.awsService.uploadPublicFile(file.buffer, file.originalname);
            if (uploadResult == undefined) return response.status(500).json('Failed to upload file');
            return response.status(200).json(uploadResult)
        } catch (error) {
            return response
            .status(500)
            .json('Failed to upload file:' + error.message);
        }
    }

    @Get()
    async getFiles(): Promise<any[]> {
      return this.awsService.getFiles();
    }

    @Get(':id')
    async getFileById(@Param('id') id: string): Promise<any> {
       //return this.awsService.getDecryptedFileById(id);
       return this.awsService.getFileById(id);
    }
}