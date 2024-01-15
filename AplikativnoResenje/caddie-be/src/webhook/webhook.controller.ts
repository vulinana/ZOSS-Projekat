/*eslint-disable */
import { Body, Controller, Get, Headers, Post } from '@nestjs/common';
import { PullRequestService } from './pull-request.service';
import { PrDto } from './dtos/pr.dto';
import * as crypto from 'crypto';

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
}
