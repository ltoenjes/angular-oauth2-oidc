import {DateTimeProvider, SystemDateTimeProvider} from './date-time-provider';
import {OAuthLogger, OAuthStorage} from './types';
import {ModuleWithProviders, NgModule, Provider} from '@angular/core';
import {CommonModule} from '@angular/common';
import {HTTP_INTERCEPTORS} from '@angular/common/http';

import {OAuthService} from './oauth-service';
import {UrlHelperService} from './url-helper.service';

import {OAuthModuleConfig} from './oauth-module.config';
import {OAuthNoopResourceServerErrorHandler, OAuthResourceServerErrorHandler} from './interceptors/resource-server-error-handler';
import {DefaultOAuthInterceptor} from './interceptors/default-oauth.interceptor';
import {ValidationHandler} from './token-validation/validation-handler';
import {NullValidationHandler} from './token-validation/null-validation-handler';
import {createDefaultLogger, createDefaultStorage} from './factories';
import {DefaultHashHandler, HashHandler} from './token-validation/hash-handler';

@NgModule({
            imports: [CommonModule],
            declarations: [],
            exports: [],
          })
export class OAuthModule {
  static forRoot(
    config: OAuthModuleConfig = null,
    validationHandlerClass = NullValidationHandler
  ): ModuleWithProviders<OAuthModule> {
    const providers: Provider[] = [
      OAuthService,
      UrlHelperService,
      {provide: OAuthLogger, useFactory: createDefaultLogger},
      {provide: OAuthStorage, useFactory: createDefaultStorage},
      {provide: ValidationHandler, useClass: validationHandlerClass},
      {provide: HashHandler, useClass: DefaultHashHandler},
      {
        provide: OAuthResourceServerErrorHandler,
        useClass: OAuthNoopResourceServerErrorHandler,
      },
      {provide: OAuthModuleConfig, useValue: config},
      {provide: DateTimeProvider, useClass: SystemDateTimeProvider},
    ];
    if (!config?.noInterceptor) {
      providers.push({
                       provide: HTTP_INTERCEPTORS,
                       useClass: DefaultOAuthInterceptor,
                       multi: true,
                     });
    }
    return {
      ngModule: OAuthModule,
      providers: [
        OAuthService,
        UrlHelperService,
        {provide: OAuthLogger, useFactory: createDefaultLogger},
        {provide: OAuthStorage, useFactory: createDefaultStorage},
        {provide: ValidationHandler, useClass: validationHandlerClass},
        {provide: HashHandler, useClass: DefaultHashHandler},
        {
          provide: OAuthResourceServerErrorHandler,
          useClass: OAuthNoopResourceServerErrorHandler,
        },
        {provide: OAuthModuleConfig, useValue: config},

        {provide: DateTimeProvider, useClass: SystemDateTimeProvider},
      ],
    };
  }
}
