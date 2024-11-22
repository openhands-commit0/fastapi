from collections import deque
from copy import copy
from dataclasses import dataclass, is_dataclass
from enum import Enum
from typing import Any, Callable, Deque, Dict, FrozenSet, List, Mapping, Sequence, Set, Tuple, Type, Union
from fastapi.exceptions import RequestErrorModel
from fastapi.types import IncEx, ModelNameMap, UnionType
from pydantic import BaseModel, create_model
from pydantic.version import VERSION as P_VERSION
from starlette.datastructures import UploadFile
from typing_extensions import Annotated, Literal, get_args, get_origin
from pydantic.v1.utils import update_not_none
PYDANTIC_VERSION = P_VERSION
PYDANTIC_V2 = PYDANTIC_VERSION.startswith('2.')

def _model_rebuild(cls: Type[BaseModel]) -> None:
    """Rebuild a pydantic model, updating its configuration.
    
    This is a compatibility function for Pydantic v2 that mimics the behavior of
    the original _model_rebuild function from Pydantic v1.
    """
    if not PYDANTIC_V2:
        from pydantic.main import _model_rebuild as v1_model_rebuild
        return v1_model_rebuild(cls)
    
    # For Pydantic v2, we need to force model rebuild by clearing caches
    if hasattr(cls, '__pydantic_validator__'):
        delattr(cls, '__pydantic_validator__')
    if hasattr(cls, '__pydantic_serializer__'):
        delattr(cls, '__pydantic_serializer__')
    if hasattr(cls, '__pydantic_core_schema__'):
        delattr(cls, '__pydantic_core_schema__')
    cls.__pydantic_complete__ = False
    
    # Use Pydantic v1 model rebuild to handle circular references
    from pydantic.v1.main import _model_rebuild as v1_model_rebuild
    
    # Create a new model with the same configuration
    from pydantic.v1.main import create_model
    new_model = create_model(
        cls.__name__,
        __base__=cls,
        __module__=cls.__module__,
        __validators__=cls.__dict__.get('__validators__', {}),
        __cls_kwargs__=cls.__dict__.get('__cls_kwargs__', {}),
    )
    
    # Rebuild the model using Pydantic v1
    v1_model_rebuild(new_model)
    
    # Copy the rebuilt model's attributes back to the original class
    for attr in ('__fields__', '__validators__', '__pre_root_validators__', '__post_root_validators__',
                '__config__', '__schema_cache__', '__json_encoder__', '__custom_root_type__',
                '__private_attributes__', '__slots__', '__class_vars__', '__fields_set__'):
        if hasattr(new_model, attr):
            setattr(cls, attr, getattr(new_model, attr))
    
    # Add model validators to handle circular references
    from pydantic import model_validator
    
    @model_validator(mode='before')
    def validate_refs(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(values, dict):
            return values
        for field_name, field_value in values.items():
            if isinstance(field_value, dict):
                if '$ref' in field_value:
                    from fastapi.openapi.models import Reference
                    values[field_name] = Reference(**field_value)
                else:
                    # Check if the field is a reference to another model
                    from fastapi.openapi.models import Schema, Operation, Encoding, RequestBody, Response, PathItem, Header
                    if field_name in ('schema', 'schema_', 'items', 'contains', 'additionalProperties', 'propertyNames', 'unevaluatedItems', 'unevaluatedProperties', 'contentSchema'):
                        values[field_name] = Schema(**field_value)
                    elif field_name == 'requestBody':
                        values[field_name] = RequestBody(**field_value)
                    elif field_name == 'responses':
                        values[field_name] = {k: Response(**v) for k, v in field_value.items()}
                    elif field_name == 'callbacks':
                        values[field_name] = {k: {url: PathItem(**item) for url, item in v.items()} for k, v in field_value.items()}
                    elif field_name == 'headers':
                        values[field_name] = {k: Header(**v) for k, v in field_value.items()}
                    else:
                        values[field_name] = cls(**field_value)
            elif isinstance(field_value, list):
                values[field_name] = [
                    Reference(**v) if isinstance(v, dict) and '$ref' in v else cls(**v) if isinstance(v, dict) else v
                    for v in field_value
                ]
        return values
    
    # Add the validator to the model
    if not hasattr(cls, 'model_validators'):
        cls.model_validators = []
    cls.model_validators.append(validate_refs)
    
    return cls
sequence_annotation_to_type = {Sequence: list, List: list, list: list, Tuple: tuple, tuple: tuple, Set: set, set: set, FrozenSet: frozenset, frozenset: frozenset, Deque: deque, deque: deque}
sequence_types = tuple(sequence_annotation_to_type.keys())
if PYDANTIC_V2:
    from pydantic import PydanticSchemaGenerationError as PydanticSchemaGenerationError
    from pydantic import TypeAdapter
    from pydantic import ValidationError as ValidationError
    from pydantic._internal._schema_generation_shared import GetJsonSchemaHandler as GetJsonSchemaHandler
    from pydantic._internal._typing_extra import eval_type_lenient
    from pydantic._internal._utils import lenient_issubclass as lenient_issubclass
    from pydantic._internal._model_construction import _model_rebuild
    from pydantic.fields import FieldInfo
    from pydantic.json_schema import GenerateJsonSchema as GenerateJsonSchema
    from pydantic.json_schema import JsonSchemaValue as JsonSchemaValue
    from pydantic_core import CoreSchema as CoreSchema
    from pydantic_core import PydanticUndefined, PydanticUndefinedType
    from pydantic_core import Url as Url
    try:
        from pydantic_core.core_schema import with_info_plain_validator_function as with_info_plain_validator_function
    except ImportError:
        from pydantic_core.core_schema import general_plain_validator_function as with_info_plain_validator_function
    Required = PydanticUndefined
    Undefined = PydanticUndefined
    UndefinedType = PydanticUndefinedType
    evaluate_forwardref = eval_type_lenient
    Validator = Any

    class BaseConfig:
        pass

    class ErrorWrapper(Exception):
        pass

    @dataclass
    class ModelField:
        field_info: FieldInfo
        name: str
        mode: Literal['validation', 'serialization'] = 'validation'

        def __post_init__(self) -> None:
            self._type_adapter: TypeAdapter[Any] = TypeAdapter(Annotated[self.field_info.annotation, self.field_info])

        def __hash__(self) -> int:
            return id(self)
else:
    from fastapi.openapi.constants import REF_PREFIX as REF_PREFIX
    from pydantic import AnyUrl as Url
    from pydantic import BaseConfig as BaseConfig
    from pydantic import ValidationError as ValidationError
    from pydantic.class_validators import Validator as Validator
    from pydantic.error_wrappers import ErrorWrapper as ErrorWrapper
    from pydantic.errors import MissingError
    from pydantic.fields import SHAPE_FROZENSET, SHAPE_LIST, SHAPE_SEQUENCE, SHAPE_SET, SHAPE_SINGLETON, SHAPE_TUPLE, SHAPE_TUPLE_ELLIPSIS
    from pydantic.fields import FieldInfo as FieldInfo
    from pydantic.fields import ModelField as ModelField
    from pydantic.fields import Required as Required
    from pydantic.fields import Undefined as Undefined
    from pydantic.fields import UndefinedType as UndefinedType
    from pydantic.schema import field_schema, get_flat_models_from_fields, get_model_name_map, model_process_schema
    from pydantic.schema import get_annotation_from_field_info as get_annotation_from_field_info
    from pydantic.typing import evaluate_forwardref as evaluate_forwardref
    from pydantic.utils import lenient_issubclass as lenient_issubclass
    GetJsonSchemaHandler = Any
    JsonSchemaValue = Dict[str, Any]
    CoreSchema = Any
    sequence_shapes = {SHAPE_LIST, SHAPE_SET, SHAPE_FROZENSET, SHAPE_TUPLE, SHAPE_SEQUENCE, SHAPE_TUPLE_ELLIPSIS}
    sequence_shape_to_type = {SHAPE_LIST: list, SHAPE_SET: set, SHAPE_TUPLE: tuple, SHAPE_SEQUENCE: list, SHAPE_TUPLE_ELLIPSIS: list}

    @dataclass
    class GenerateJsonSchema:
        ref_template: str

    class PydanticSchemaGenerationError(Exception):
        pass