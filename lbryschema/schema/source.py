from copy import deepcopy
from lbryschema.schema import source_pb2 as source_pb, VERSION_MAP
from lbryschema.schema import SOURCE_TYPES, LBRY_SD_HASH_LENGTH, BTIH_LENGTH
from lbryschema.schema import LBRY_SD_HASH, BTIH, HTTP
from lbryschema.schema.schema import Schema
from lbryschema.error import InvalidSourceHashLength, UnknownSourceType


class Source(Schema):
    @classmethod
    def load(cls, message):
        _source = deepcopy(message)
        sd_hash = _source.pop('source')
        _message_pb = source_pb.Source()
        _message_pb.version = VERSION_MAP[_source.pop("version")]
        _message_pb.sourceType = SOURCE_TYPES[_source.pop('sourceType')]
        _message_pb.source = sd_hash
        _message_pb.contentType = _source.pop('contentType')
        
        if _message_pb.sourceType == SOURCE_TYPES[LBRY_SD_HASH]:
            if len(sd_hash) != LBRY_SD_HASH_LENGTH:
                raise InvalidSourceHashLength(len(sd_hash))
        elif _message_pb.sourceType == SOURCE_TYPES[BTIH]:
            if len(sd_hash) != BTIH_LENGTH:
                raise InvalidSourceHashLength(len(sd_hash))
        elif _message_pb.sourceType == SOURCE_TYPES[HTTP]:
            if sd_hash[:4] != "http":
                raise UnknownSourceType(len(sd_hash))
        else:
            assert UnknownSourceType(len(sd_hash))
        
        return cls._load(_source, _message_pb)
