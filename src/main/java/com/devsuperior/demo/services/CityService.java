package com.devsuperior.demo.services;

import java.io.Serializable;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.devsuperior.demo.dto.CityDTO;
import com.devsuperior.demo.entities.City;
import com.devsuperior.demo.repositories.CityRepository;


@Service
public class CityService implements Serializable{
	private static final long serialVersionUID = 1L;
	
	@Autowired
	private CityRepository repository;
	
	@Transactional(readOnly = true)
	public List<CityDTO> findAll() {
		List<City> page = repository.findAll(Sort.by("name"));
		return page.stream().map(x -> new CityDTO(x)).toList();
	}
	
	@Transactional
	public CityDTO insert(CityDTO dto) {
		City entity = new City(null, dto.getName());
		//entity.setName(dto.getName());
		entity = repository.save(entity);
		return new CityDTO(entity);
	}
}
