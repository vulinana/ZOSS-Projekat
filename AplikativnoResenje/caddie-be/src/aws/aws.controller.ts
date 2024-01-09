import { Controller, Post, Get, Req, Res, UploadedFile, UseInterceptors } from "@nestjs/common";
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
            const uploadResult = await this.awsService.uploadPublicFile(file.buffer, file.originalname);
            return response.status(200).json(uploadResult)
        } catch (error) {
            return response
            .status(5000)
            .json('Failed to upload image file:' + error.message);
        }
    }

    @Get()
    async getFiles(): Promise<any[]> {
      return this.awsService.getFiles();
    }
}