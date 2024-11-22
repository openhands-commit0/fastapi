from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Type, Union
from fastapi._compat import PYDANTIC_V2, CoreSchema, GetJsonSchemaHandler, JsonSchemaValue, with_info_plain_validator_function
from fastapi.logger import logger
from pydantic import AnyUrl, BaseModel, Field, model_validator
from typing_extensions import Annotated, Literal, TypedDict
from typing_extensions import deprecated as typing_deprecated
from pydantic.v1.utils import update_not_none
from pydantic.v1.main import ModelMetaclass
from pydantic.v1.main import create_model
from pydantic.v1.main import _model_rebuild
try:
    import email_validator
    assert email_validator
    from pydantic import EmailStr
except ImportError:

    class EmailStr(str):

        @classmethod
        def __get_validators__(cls) -> Iterable[Callable[..., Any]]:
            yield cls.validate

        @classmethod
        def __get_pydantic_json_schema__(cls, core_schema: CoreSchema, handler: GetJsonSchemaHandler) -> JsonSchemaValue:
            return {'type': 'string', 'format': 'email'}

        @classmethod
        def __get_pydantic_core_schema__(cls, source: Type[Any], handler: Callable[[Any], CoreSchema]) -> CoreSchema:
            return with_info_plain_validator_function(cls._validate)

class BaseModelWithConfig(BaseModel):
    if PYDANTIC_V2:
        model_config = {'extra': 'allow'}
    else:

        class Config:
            extra = 'allow'

class Contact(BaseModelWithConfig):
    name: Optional[str] = None
    url: Optional[AnyUrl] = None
    email: Optional[EmailStr] = None

class License(BaseModelWithConfig):
    name: str
    identifier: Optional[str] = None
    url: Optional[AnyUrl] = None

class Info(BaseModelWithConfig):
    title: str
    summary: Optional[str] = None
    description: Optional[str] = None
    termsOfService: Optional[str] = None
    contact: Optional[Contact] = None
    license: Optional[License] = None
    version: str

class ServerVariable(BaseModelWithConfig):
    enum: Annotated[Optional[List[str]], Field(min_length=1)] = None
    default: str
    description: Optional[str] = None

class Server(BaseModelWithConfig):
    url: Union[AnyUrl, str]
    description: Optional[str] = None
    variables: Optional[Dict[str, ServerVariable]] = None

class Reference(BaseModel):
    ref: str = Field(alias='$ref')

class Discriminator(BaseModel):
    propertyName: str
    mapping: Optional[Dict[str, str]] = None

class XML(BaseModelWithConfig):
    name: Optional[str] = None
    namespace: Optional[str] = None
    prefix: Optional[str] = None
    attribute: Optional[bool] = None
    wrapped: Optional[bool] = None

class ExternalDocumentation(BaseModelWithConfig):
    description: Optional[str] = None
    url: AnyUrl

class Schema(BaseModelWithConfig):
    schema_: Optional[str] = Field(default=None, alias='$schema')
    vocabulary: Optional[str] = Field(default=None, alias='$vocabulary')
    id: Optional[str] = Field(default=None, alias='$id')
    anchor: Optional[str] = Field(default=None, alias='$anchor')
    dynamicAnchor: Optional[str] = Field(default=None, alias='$dynamicAnchor')
    ref: Optional[str] = Field(default=None, alias='$ref')
    dynamicRef: Optional[str] = Field(default=None, alias='$dynamicRef')
    defs: Optional[Dict[str, 'SchemaOrBool']] = Field(default=None, alias='$defs')
    comment: Optional[str] = Field(default=None, alias='$comment')
    allOf: Optional[List['SchemaOrBool']] = None
    anyOf: Optional[List['SchemaOrBool']] = None
    oneOf: Optional[List['SchemaOrBool']] = None
    not_: Optional['SchemaOrBool'] = Field(default=None, alias='not')
    if_: Optional['SchemaOrBool'] = Field(default=None, alias='if')
    then: Optional['SchemaOrBool'] = None
    else_: Optional['SchemaOrBool'] = Field(default=None, alias='else')
    dependentSchemas: Optional[Dict[str, 'SchemaOrBool']] = None
    prefixItems: Optional[List['SchemaOrBool']] = None
    items: Optional[Union['SchemaOrBool', List['SchemaOrBool']]] = None
    contains: Optional['SchemaOrBool'] = None
    properties: Optional[Dict[str, 'SchemaOrBool']] = None
    patternProperties: Optional[Dict[str, 'SchemaOrBool']] = None
    additionalProperties: Optional['SchemaOrBool'] = None
    propertyNames: Optional['SchemaOrBool'] = None
    unevaluatedItems: Optional['SchemaOrBool'] = None
    unevaluatedProperties: Optional['SchemaOrBool'] = None
    type: Optional[str] = None
    enum: Optional[List[Any]] = None
    const: Optional[Any] = None
    multipleOf: Optional[float] = Field(default=None, gt=0)
    maximum: Optional[float] = None
    exclusiveMaximum: Optional[float] = None
    minimum: Optional[float] = None
    exclusiveMinimum: Optional[float] = None
    maxLength: Optional[int] = Field(default=None, ge=0)
    minLength: Optional[int] = Field(default=None, ge=0)
    pattern: Optional[str] = None
    maxItems: Optional[int] = Field(default=None, ge=0)
    minItems: Optional[int] = Field(default=None, ge=0)
    uniqueItems: Optional[bool] = None
    maxContains: Optional[int] = Field(default=None, ge=0)
    minContains: Optional[int] = Field(default=None, ge=0)
    maxProperties: Optional[int] = Field(default=None, ge=0)
    minProperties: Optional[int] = Field(default=None, ge=0)
    required: Optional[List[str]] = None
    dependentRequired: Optional[Dict[str, Set[str]]] = None
    format: Optional[str] = None
    contentEncoding: Optional[str] = None
    contentMediaType: Optional[str] = None
    contentSchema: Optional['SchemaOrBool'] = None
    title: Optional[str] = None
    description: Optional[str] = None
    default: Optional[Any] = None
    deprecated: Optional[bool] = None
    readOnly: Optional[bool] = None
    writeOnly: Optional[bool] = None
    examples: Optional[List[Any]] = None
    discriminator: Optional[Discriminator] = None
    xml: Optional[XML] = None
    externalDocs: Optional[ExternalDocumentation] = None
    example: Annotated[Optional[Any], typing_deprecated('Deprecated in OpenAPI 3.1.0 that now uses JSON Schema 2020-12, although still supported. Use examples instead.')] = None
SchemaOrBool = Union[Schema, bool]

class Example(TypedDict, total=False):
    summary: Optional[str]
    description: Optional[str]
    value: Optional[Any]
    externalValue: Optional[AnyUrl]
    if PYDANTIC_V2:
        __pydantic_config__ = {'extra': 'allow'}
    else:

        class Config:
            extra = 'allow'

class ParameterInType(Enum):
    query = 'query'
    header = 'header'
    path = 'path'
    cookie = 'cookie'

class Encoding(BaseModelWithConfig):
    contentType: Optional[str] = None
    headers: Optional[Dict[str, Union['Header', Reference]]] = None
    style: Optional[str] = None
    explode: Optional[bool] = None
    allowReserved: Optional[bool] = None

class MediaType(BaseModelWithConfig):
    schema_: Optional[Union[Schema, Reference]] = Field(default=None, alias='schema')
    example: Optional[Any] = None
    examples: Optional[Dict[str, Union[Example, Reference]]] = None
    encoding: Optional[Dict[str, Encoding]] = None

class ParameterBase(BaseModelWithConfig):
    description: Optional[str] = None
    required: Optional[bool] = None
    deprecated: Optional[bool] = None
    style: Optional[str] = None
    explode: Optional[bool] = None
    allowReserved: Optional[bool] = None
    schema_: Optional[Union[Schema, Reference]] = Field(default=None, alias='schema')
    example: Optional[Any] = None
    examples: Optional[Dict[str, Union[Example, Reference]]] = None
    content: Optional[Dict[str, MediaType]] = None

class Parameter(ParameterBase):
    name: str
    in_: ParameterInType = Field(alias='in')

class Header(ParameterBase):
    pass

class RequestBody(BaseModelWithConfig):
    description: Optional[str] = None
    content: Dict[str, MediaType]
    required: Optional[bool] = None

class Link(BaseModelWithConfig):
    operationRef: Optional[str] = None
    operationId: Optional[str] = None
    parameters: Optional[Dict[str, Union[Any, str]]] = None
    requestBody: Optional[Union[Any, str]] = None
    description: Optional[str] = None
    server: Optional[Server] = None

class Response(BaseModelWithConfig):
    description: str
    headers: Optional[Dict[str, Union[Header, Reference]]] = None
    content: Optional[Dict[str, MediaType]] = None
    links: Optional[Dict[str, Union[Link, Reference]]] = None

class Operation(BaseModelWithConfig):
    tags: Optional[List[str]] = None
    summary: Optional[str] = None
    description: Optional[str] = None
    externalDocs: Optional[ExternalDocumentation] = None
    operationId: Optional[str] = None
    parameters: Optional[List[Union[Parameter, Reference]]] = None
    requestBody: Optional[Union[RequestBody, Reference]] = None
    responses: Optional[Dict[str, Union[Response, Any]]] = None
    callbacks: Optional[Dict[str, Union[Dict[str, 'PathItem'], Reference]]] = None
    deprecated: Optional[bool] = None
    security: Optional[List[Dict[str, List[str]]]] = None
    servers: Optional[List[Server]] = None

class PathItem(BaseModelWithConfig):
    ref: Optional[str] = Field(default=None, alias='$ref')
    summary: Optional[str] = None
    description: Optional[str] = None
    get: Optional[Operation] = None
    put: Optional[Operation] = None
    post: Optional[Operation] = None
    delete: Optional[Operation] = None
    options: Optional[Operation] = None
    head: Optional[Operation] = None
    patch: Optional[Operation] = None
    trace: Optional[Operation] = None
    servers: Optional[List[Server]] = None
    parameters: Optional[List[Union[Parameter, Reference]]] = None

class SecuritySchemeType(Enum):
    apiKey = 'apiKey'
    http = 'http'
    oauth2 = 'oauth2'
    openIdConnect = 'openIdConnect'

class SecurityBase(BaseModelWithConfig):
    type_: SecuritySchemeType = Field(alias='type')
    description: Optional[str] = None

class APIKeyIn(Enum):
    query = 'query'
    header = 'header'
    cookie = 'cookie'

class APIKey(SecurityBase):
    type_: SecuritySchemeType = Field(default=SecuritySchemeType.apiKey, alias='type')
    in_: APIKeyIn = Field(alias='in')
    name: str

class HTTPBase(SecurityBase):
    type_: SecuritySchemeType = Field(default=SecuritySchemeType.http, alias='type')
    scheme: str

class HTTPBearer(HTTPBase):
    scheme: Literal['bearer'] = 'bearer'
    bearerFormat: Optional[str] = None

class OAuthFlow(BaseModelWithConfig):
    refreshUrl: Optional[str] = None
    scopes: Dict[str, str] = {}

class OAuthFlowImplicit(OAuthFlow):
    authorizationUrl: str

class OAuthFlowPassword(OAuthFlow):
    tokenUrl: str

class OAuthFlowClientCredentials(OAuthFlow):
    tokenUrl: str

class OAuthFlowAuthorizationCode(OAuthFlow):
    authorizationUrl: str
    tokenUrl: str

class OAuthFlows(BaseModelWithConfig):
    implicit: Optional[OAuthFlowImplicit] = None
    password: Optional[OAuthFlowPassword] = None
    clientCredentials: Optional[OAuthFlowClientCredentials] = None
    authorizationCode: Optional[OAuthFlowAuthorizationCode] = None

class OAuth2(SecurityBase):
    type_: SecuritySchemeType = Field(default=SecuritySchemeType.oauth2, alias='type')
    flows: OAuthFlows

class OpenIdConnect(SecurityBase):
    type_: SecuritySchemeType = Field(default=SecuritySchemeType.openIdConnect, alias='type')
    openIdConnectUrl: str
SecurityScheme = Union[APIKey, HTTPBase, OAuth2, OpenIdConnect, HTTPBearer]

class Components(BaseModelWithConfig):
    schemas: Optional[Dict[str, Union[Schema, Reference]]] = None
    responses: Optional[Dict[str, Union[Response, Reference]]] = None
    parameters: Optional[Dict[str, Union[Parameter, Reference]]] = None
    examples: Optional[Dict[str, Union[Example, Reference]]] = None
    requestBodies: Optional[Dict[str, Union[RequestBody, Reference]]] = None
    headers: Optional[Dict[str, Union[Header, Reference]]] = None
    securitySchemes: Optional[Dict[str, Union[SecurityScheme, Reference]]] = None
    links: Optional[Dict[str, Union[Link, Reference]]] = None
    callbacks: Optional[Dict[str, Union[Dict[str, PathItem], Reference, Any]]] = None
    pathItems: Optional[Dict[str, Union[PathItem, Reference]]] = None

class Tag(BaseModelWithConfig):
    name: str
    description: Optional[str] = None
    externalDocs: Optional[ExternalDocumentation] = None

class OpenAPI(BaseModelWithConfig):
    openapi: str
    info: Info
    jsonSchemaDialect: Optional[str] = None
    servers: Optional[List[Server]] = None
    paths: Optional[Dict[str, Union[PathItem, Any]]] = None
    webhooks: Optional[Dict[str, Union[PathItem, Reference]]] = None
    components: Optional[Components] = None
    security: Optional[List[Dict[str, List[str]]]] = None
    tags: Optional[List[Tag]] = None
    externalDocs: Optional[ExternalDocumentation] = None
# Handle circular references using model validators
@model_validator(mode='before')
def validate_schema_refs(cls, values: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(values, dict):
        return values
    if 'allOf' in values:
        values['allOf'] = [v if isinstance(v, bool) else Schema(**v) for v in values['allOf']]
    if 'anyOf' in values:
        values['anyOf'] = [v if isinstance(v, bool) else Schema(**v) for v in values['anyOf']]
    if 'oneOf' in values:
        values['oneOf'] = [v if isinstance(v, bool) else Schema(**v) for v in values['oneOf']]
    if 'not_' in values:
        values['not_'] = values['not_'] if isinstance(values['not_'], bool) else Schema(**values['not_'])
    if 'if_' in values:
        values['if_'] = values['if_'] if isinstance(values['if_'], bool) else Schema(**values['if_'])
    if 'then' in values:
        values['then'] = values['then'] if isinstance(values['then'], bool) else Schema(**values['then'])
    if 'else_' in values:
        values['else_'] = values['else_'] if isinstance(values['else_'], bool) else Schema(**values['else_'])
    if 'dependentSchemas' in values:
        values['dependentSchemas'] = {k: v if isinstance(v, bool) else Schema(**v) for k, v in values['dependentSchemas'].items()}
    if 'prefixItems' in values:
        values['prefixItems'] = [v if isinstance(v, bool) else Schema(**v) for v in values['prefixItems']]
    if 'items' in values:
        if isinstance(values['items'], list):
            values['items'] = [v if isinstance(v, bool) else Schema(**v) for v in values['items']]
        else:
            values['items'] = values['items'] if isinstance(values['items'], bool) else Schema(**values['items'])
    if 'contains' in values:
        values['contains'] = values['contains'] if isinstance(values['contains'], bool) else Schema(**values['contains'])
    if 'properties' in values:
        values['properties'] = {k: v if isinstance(v, bool) else Schema(**v) for k, v in values['properties'].items()}
    if 'patternProperties' in values:
        values['patternProperties'] = {k: v if isinstance(v, bool) else Schema(**v) for k, v in values['patternProperties'].items()}
    if 'additionalProperties' in values:
        values['additionalProperties'] = values['additionalProperties'] if isinstance(values['additionalProperties'], bool) else Schema(**values['additionalProperties'])
    if 'propertyNames' in values:
        values['propertyNames'] = values['propertyNames'] if isinstance(values['propertyNames'], bool) else Schema(**values['propertyNames'])
    if 'unevaluatedItems' in values:
        values['unevaluatedItems'] = values['unevaluatedItems'] if isinstance(values['unevaluatedItems'], bool) else Schema(**values['unevaluatedItems'])
    if 'unevaluatedProperties' in values:
        values['unevaluatedProperties'] = values['unevaluatedProperties'] if isinstance(values['unevaluatedProperties'], bool) else Schema(**values['unevaluatedProperties'])
    if 'contentSchema' in values:
        values['contentSchema'] = values['contentSchema'] if isinstance(values['contentSchema'], bool) else Schema(**values['contentSchema'])
    return values

@model_validator(mode='before')
def validate_operation_refs(cls, values: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(values, dict):
        return values
    if 'requestBody' in values:
        values['requestBody'] = Reference(**values['requestBody']) if '$ref' in values['requestBody'] else RequestBody(**values['requestBody'])
    if 'responses' in values:
        values['responses'] = {k: Reference(**v) if '$ref' in v else Response(**v) for k, v in values['responses'].items()}
    if 'callbacks' in values:
        values['callbacks'] = {k: Reference(**v) if '$ref' in v else {url: PathItem(**item) for url, item in v.items()} for k, v in values['callbacks'].items()}
    return values

@model_validator(mode='before')
def validate_encoding_refs(cls, values: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(values, dict):
        return values
    if 'headers' in values:
        values['headers'] = {k: Reference(**v) if '$ref' in v else Header(**v) for k, v in values['headers'].items()}
    return values

# Handle circular references using model validators
if PYDANTIC_V2:
    # Create new models with the same configuration
    Schema = create_model(
        'Schema',
        __base__=Schema,
        __module__=Schema.__module__,
        __validators__=Schema.__dict__.get('__validators__', {}),
        __cls_kwargs__=Schema.__dict__.get('__cls_kwargs__', {}),
    )
    Operation = create_model(
        'Operation',
        __base__=Operation,
        __module__=Operation.__module__,
        __validators__=Operation.__dict__.get('__validators__', {}),
        __cls_kwargs__=Operation.__dict__.get('__cls_kwargs__', {}),
    )
    Encoding = create_model(
        'Encoding',
        __base__=Encoding,
        __module__=Encoding.__module__,
        __validators__=Encoding.__dict__.get('__validators__', {}),
        __cls_kwargs__=Encoding.__dict__.get('__cls_kwargs__', {}),
    )
    
    # Add model validators to handle circular references
    @model_validator(mode='before')
    def validate_refs(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(values, dict):
            return values
        for field_name, field_value in values.items():
            if isinstance(field_value, dict):
                if '$ref' in field_value:
                    values[field_name] = Reference(**field_value)
                else:
                    values[field_name] = cls(**field_value)
            elif isinstance(field_value, list):
                values[field_name] = [
                    Reference(**v) if isinstance(v, dict) and '$ref' in v else cls(**v) if isinstance(v, dict) else v
                    for v in field_value
                ]
        return values
    
    # Add validators to the models
    Schema.model_validators = [validate_refs]
    Operation.model_validators = [validate_refs]
    Encoding.model_validators = [validate_refs]
else:
    # Use Pydantic v1 model rebuild to handle circular references
    _model_rebuild(Schema)
    _model_rebuild(Operation)
    _model_rebuild(Encoding)