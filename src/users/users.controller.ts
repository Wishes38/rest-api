import { BadRequestException, Body, Controller, Get, Post, UseGuards, Request } from '@nestjs/common';
import { UsersService } from './users.service';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RolesGuard } from '../auth/roles.guard';
import { Roles } from '../auth/roles.decorator';

@Controller('users')
@UseGuards(JwtAuthGuard, RolesGuard)
export class UsersController {
    constructor(private readonly usersService: UsersService) { }

    @Post('register')
    async register(
        @Body() body: { email: string; password: string; roles?: string[] },
    ) {
        const { email, password, roles } = body;

        const existingUser = await this.usersService.findUserByEmail(email);
        if (existingUser) {
            throw new BadRequestException('User already exists');
        }

        return this.usersService.createUser(email, password, roles);
    }

    @Roles('user','admin')
    @Get('my-profile')
    getUserProfile(@Request() req) {
        return { message: 'Welcome User', user: req.user };
    }

    @Roles('admin')
    @Get('profile')
    getAdminProfile(@Request() req) {
        return { message: 'Welcome Admin', user: req.user };
    }
}
