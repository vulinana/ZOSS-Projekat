/*eslint-disable */
import {
  Body,
  Controller,
  ForbiddenException,
  Get,
  Headers,
  Param,
  Post,
  Req,
  UseGuards
} from '@nestjs/common';
import { PullRequestService } from './pull-request.service';
import { PrDto } from './dtos/pr.dto';
import * as crypto from 'crypto';
import { JwtGuard } from './strategies/jwt.guard';
import { Request } from 'express';

@Controller('prs')
export class WebhookController {
  constructor(private readonly prService: PullRequestService) {}
  @Post('/webhook')
  async webhook(
    @Body() data: any,
    @Headers('X-Github-Event') eventType: string,
    @Headers() headers: any
  ) {
    if (eventType !== 'pull_request' || data?.action !== 'opened')
      return { status: 'SUCCESS' };

    const dto: PrDto = {
      author: data.pull_request.user.login,
      number: data.pull_request.number,
      githubId: data.pull_request.node_id,
      title: data.pull_request.title,
      body: data.pull_request.body
    };
    await this.prService.save(dto);

    return { status: 'Success' };
  }

  @Post('/webhook/protected')
  async protectedWebhook(
    @Body() data: any,
    @Headers('X-Github-Event') eventType: string,
    @Headers() headers: any
  ) {
    const signature = headers['x-hub-signature-256'];
    const payload = JSON.stringify(data);

    if (!signature || !payload) {
      return { status: "Signature doesn't exist!" };
    }

    const secret = 'YOUR_SECRET'; // Replace with your GitHub webhook secret
    const expectedSignature = `sha256=${crypto
      .createHmac('sha256', secret)
      .update(payload)
      .digest('hex')}`;

    if (signature !== expectedSignature) {
      return { status: 'Signature is not valid!' };
    }
    console.log(eventType, headers);
    console.log(data);
    if (eventType !== 'pull_request' || data?.action !== 'opened')
      return { status: 'SUCCESS' };

    const dto: PrDto = {
      author: data.pull_request.user.login,
      number: data.pull_request.number,
      githubId: data.pull_request.node_id,
      title: data.pull_request.title,
      body: data.pull_request.body
    };
    await this.prService.save(dto);

    return { status: 'Success' };
  }

  @Get('/')
  async getPrs() {
    return this.prService.findAll();
  }

  @UseGuards(JwtGuard)
  @Get('/:username')
  async getByUsername(
    @Req() { user }: Request & { user: { email: string; username: string } },
    @Param('username') username: string
  ) {
    const prs = await this.prService.getAllByAuthor(username);
    return prs;
  }

  @UseGuards(JwtGuard)
  @Get('/:username/protected')
  async getByUsernameProtected(
    @Req() { user }: Request & { user: { email: string; username: string } },
    @Param('username') username: string
  ) {
    if (user.username !== username)
      throw new ForbiddenException(
        'Unauthorized access. Use username that belongs to you!'
      );
    const prs = await this.prService.getAllByAuthor(username);
    return prs;
  }
}
