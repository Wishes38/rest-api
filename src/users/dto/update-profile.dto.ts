import { ApiProperty } from '@nestjs/swagger';
import { IsOptional, IsEmail, MinLength } from 'class-validator';

export class UpdateProfileDto {
    
    @ApiProperty({ example: 'user@example.com', description: 'Email of the user', required: false })
    @IsOptional()
    @IsEmail()
    email?: string;

    @ApiProperty({ example: 'password123', description: 'New password for the user', required: false })
    @IsOptional()
    @MinLength(6)
    password?: string;

    @ApiProperty({ example: 'Jon', description: 'First name of the user', required: false })
    @IsOptional()
    firstName?: string;

    @ApiProperty({ example: 'Snow', description: 'Last name of the user', required: false })
    @IsOptional()
    lastName?: string;

}
