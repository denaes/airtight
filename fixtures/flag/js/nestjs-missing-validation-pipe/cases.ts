import { Controller, Post, Put, Patch, Body, Param } from '@nestjs/common';

@Controller('users')
export class UsersController {
  @Post()
  createUser(@Body() body: any) {
    return body;
  }

  @Post('admin')
  createAdmin(@Param('id') id: string, @Body() data: Record<string, any>) {
    return data;
  }

  @Put(':id')
  updateUser(@Param('id') id: string, @Body() updateDto: any) {
    return updateDto;
  }

  @Patch(':id')
  patchUser(@Body() patchDto: any) {
    return patchDto;
  }
}
