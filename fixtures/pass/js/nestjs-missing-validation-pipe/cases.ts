import { Controller, Post, Put, Body, Param, UsePipes, ValidationPipe, Get } from '@nestjs/common';
import { IsString, IsNotEmpty } from 'class-validator';

@Controller('users')
@UsePipes(new ValidationPipe({ whitelist: true }))
export class SafeUsersController {
  @Post()
  createUser(@Body() body: any) {
    return body;
  }

  @Put(':id')
  updateUser(@Param('id') id: string, @Body(new ValidationPipe()) updateDto: any) {
    return updateDto;
  }

  @Get()
  listUsers() {
    return [];
  }
}
